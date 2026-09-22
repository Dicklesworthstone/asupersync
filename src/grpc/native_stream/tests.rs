//! State-retention and protocol regressions; native socket journeys are below.
#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::grpc::codec::IdentityCodec;
use crate::time::VirtualClock;
use crate::types::{Budget, RegionId, TaskId};
use std::io;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

#[derive(Default)]
struct Probe {
    writes: Mutex<Vec<u8>>,
    read_calls: AtomicUsize,
    position: AtomicUsize,
    readable: AtomicUsize,
    drops: AtomicUsize,
}

struct FixtureIo {
    bytes: Vec<u8>,
    probe: Arc<Probe>,
    max_chunk: usize,
    eof: bool,
}

impl AsyncRead for FixtureIo {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.probe.read_calls.fetch_add(1, Ordering::SeqCst);
        let position = this.probe.position.load(Ordering::SeqCst);
        let end = this.bytes.len().min(this.probe.readable.load(Ordering::SeqCst));
        if position == end {
            return if this.eof && position == this.bytes.len() { Poll::Ready(Ok(())) } else { Poll::Pending };
        }
        let length = (end - position).min(this.max_chunk).min(buf.remaining());
        buf.put_slice(&this.bytes[position..position + length]);
        this.probe.position.store(position + length, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FixtureIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let length = bytes.len().min(self.max_chunk);
        self.probe.writes.lock().unwrap().extend_from_slice(&bytes[..length]);
        Poll::Ready(Ok(length))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

impl Drop for FixtureIo {
    fn drop(&mut self) { self.probe.drops.fetch_add(1, Ordering::SeqCst); }
}

fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap();
    assert!(len <= 16384);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&len.to_be_bytes()[1..]);
    bytes.extend_from_slice(&[kind, flags]);
    bytes.extend_from_slice(&(if kind == 4 { 0_u32 } else { 1_u32 }).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn headers(fields: &[(&str, &str)], terminal: bool) -> Vec<u8> {
    let mut block = Vec::new();
    for (key, value) in fields {
        assert!(key.len() < 127 && value.len() < 127);
        block.extend_from_slice(&[0, u8::try_from(key.len()).unwrap()]);
        block.extend_from_slice(key.as_bytes());
        block.push(u8::try_from(value.len()).unwrap());
        block.extend_from_slice(value.as_bytes());
    }
    frame(1, if terminal { 5 } else { 4 }, &block)
}

fn start() -> Vec<u8> {
    let mut bytes = frame(4, 0, &[]);
    bytes.extend(headers(&[(":status", "200"), ("content-type", "application/grpc"), ("x-initial", "first")], false));
    bytes
}

fn message(bytes: &[u8]) -> Vec<u8> {
    let mut wire = vec![0];
    wire.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(bytes);
    wire
}

fn fixture(bytes: Vec<u8>, max_chunk: usize, eof: bool) -> (FixtureIo, Arc<Probe>) {
    let probe = Arc::new(Probe::default());
    probe.readable.store(bytes.len(), Ordering::SeqCst);
    (FixtureIo { bytes, probe: Arc::clone(&probe), max_chunk, eof }, probe)
}

fn call(io: FixtureIo) -> NativeServerStream<FixtureIo, IdentityCodec> {
    NativeServerStream::new(&Cx::for_testing(), io, "localhost", "/test.Service/Watch",
        Request::new(Bytes::from_static(b"request-once")), IdentityCodec, NativeStreamConfig::default()).unwrap()
}

fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut task = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut task) { return value; }
    }
    panic!("fixture failed to complete within bounded polls");
}

#[test]
fn native_client_preserves_fragmented_messages_metadata_and_error_then_fuses() {
    let mut bytes = start();
    let mut payload = message(b"alpha");
    payload.extend(message(b"beta"));
    for chunk in payload.chunks(3) { bytes.extend(frame(0, 0, chunk)); }
    bytes.extend(headers(&[("grpc-status", "3"), ("grpc-message", "bad%20%25"), ("x-trailer-bin", "AP8")], true));
    let (io, probe) = fixture(bytes, 2, false);
    let mut call = call(io);
    assert!(probe.writes.lock().unwrap().is_empty(), "construction must not write");
    assert!(run(call.headers()).unwrap().get("x-initial").is_some());
    assert_eq!(run(call.message()).unwrap().unwrap().as_ref(), b"alpha");
    assert_eq!(run(call.message()).unwrap().unwrap().as_ref(), b"beta");
    let error = run(call.message()).unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.message(), "bad %");
    assert!(call.trailers().unwrap().get("x-trailer-bin").is_some());
    assert!(run(call.message()).unwrap().is_none());
    assert_eq!(call.status().unwrap().code(), Code::InvalidArgument);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn interrupted_message_wait_retains_partial_data_and_sends_request_once() {
    let mut bytes = start();
    let wire = message(b"resumed");
    bytes.extend(frame(0, 0, &wire[..3]));
    let pause = bytes.len();
    bytes.extend(frame(0, 0, &wire[3..]));
    bytes.extend(headers(&[("grpc-status", "0")], true));
    let (io, probe) = fixture(bytes, 3, false);
    probe.readable.store(pause, Ordering::SeqCst);
    let mut call = call(io);
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut wait = Box::pin(call.message());
        for _ in 0..1024 {
            assert!(wait.as_mut().poll(&mut task).is_pending());
            if probe.position.load(Ordering::SeqCst) == pause { break; }
        }
        assert_eq!(probe.position.load(Ordering::SeqCst), pause);
    }
    assert_eq!(call.buffered_data_bytes(), 3);
    let reads = probe.read_calls.load(Ordering::SeqCst);
    probe.readable.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(probe.read_calls.load(Ordering::SeqCst), reads, "no detached reader");
    assert_eq!(run(call.message()).unwrap().unwrap().as_ref(), b"resumed");
    assert!(run(call.message()).unwrap().is_none());
    assert_eq!(call.status().unwrap().code(), Code::Ok);
    let writes = probe.writes.lock().unwrap();
    assert_eq!(writes.windows(CLIENT_PREFACE.len()).filter(|bytes| *bytes == CLIENT_PREFACE).count(), 1);
    assert_eq!(writes.windows(b"request-once".len()).filter(|bytes| *bytes == b"request-once").count(), 1);
}

#[test]
fn missing_status_truncation_and_oversized_prefix_never_become_success() {
    let cases = [
        (frame(0, 1, &message(b"ok")), Code::Unknown, true),
        ({ let mut x = frame(0, 0, &[0, 0, 0]); x.extend(headers(&[("grpc-status", "0")], true)); x }, Code::Internal, false),
        (frame(0, 0, &[0, 255, 255, 255, 255]), Code::ResourceExhausted, false),
        (Vec::new(), Code::Unavailable, false),
    ];
    for (suffix, expected, has_message) in cases {
        let mut bytes = start();
        bytes.extend(suffix);
        let (io, _) = fixture(bytes, 16384, true);
        let mut call = call(io);
        if has_message { assert_eq!(run(call.message()).unwrap().unwrap().as_ref(), b"ok"); }
        assert_eq!(run(call.message()).unwrap_err().code(), expected);
        assert_eq!(call.status().unwrap().code(), expected);
        assert!(run(call.message()).unwrap().is_none());
    }
}

#[test]
fn consumer_pause_does_not_read_or_replenish_credit_and_buffers_remain_bounded() {
    let mut bytes = start();
    for _ in 0..200 { bytes.extend(frame(0, 0, &message(&[7; 200]))); }
    bytes.extend(headers(&[("grpc-status", "0")], true));
    let (io, probe) = fixture(bytes, 16384, false);
    let mut call = call(io);
    for _ in 0..200 {
        assert_eq!(run(call.message()).unwrap().unwrap().len(), 200);
        let reads = probe.read_calls.load(Ordering::SeqCst);
        let writes = probe.writes.lock().unwrap().len();
        assert!(call.buffered_data_bytes() <= FRAME_BYTES);
        assert_eq!(probe.read_calls.load(Ordering::SeqCst), reads);
        assert_eq!(probe.writes.lock().unwrap().len(), writes);
    }
    assert!(run(call.message()).unwrap().is_none());
}

#[test]
fn cancellation_wakes_a_pending_read_and_releases_transport_without_changing_parent_cause() {
    struct Counter(AtomicUsize);
    impl Wake for Counter { fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); } }
    let cx = Cx::for_testing();
    let (io, probe) = fixture(start(), 16384, false);
    let mut call = NativeServerStream::new(&cx, io, "localhost", "/test.Service/Watch",
        Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default()).unwrap();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    assert!(call.poll_message(&mut task).is_pending());
    cx.cancel_with(CancelKind::CostBudget, Some("explicit test budget"));
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(call.poll_message(&mut task), Poll::Ready(Some(Err(status))) if status.code() == Code::ResourceExhausted));
    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::CostBudget);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(call.buffered_data_bytes(), 0);
}

fn timed_cx(clock: &Arc<VirtualClock>) -> Cx {
    Cx::new_with_drivers(RegionId::new_for_test(1, 0), TaskId::new_for_test(1, 0),
        Budget::INFINITE, None, None, None,
        Some(TimerDriverHandle::with_virtual_clock(Arc::clone(clock))), None)
}

#[test]
fn absolute_deadline_covers_idle_consumption_and_never_cancels_parent() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
    let cx = timed_cx(&clock);
    let mut bytes = start();
    bytes.extend(frame(0, 0, &message(b"one")));
    bytes.extend(frame(0, 0, &message(b"two")));
    let (io, probe) = fixture(bytes, 16384, false);
    let mut call = NativeServerStream::new(&cx, io, "localhost", "/test.Service/Watch",
        Request::new(Bytes::new()), IdentityCodec,
        NativeStreamConfig { timeout: Some(Duration::from_secs(2)), ..NativeStreamConfig::default() }).unwrap();
    assert_eq!(run(call.message()).unwrap().unwrap().as_ref(), b"one");
    clock.advance_to(Time::from_secs(22));
    assert_eq!(run(call.message()).unwrap_err().code(), Code::DeadlineExceeded);
    assert!(!cx.is_cancel_requested());
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn invalid_timeout_reserved_metadata_and_unavailable_timer_refuse_before_io() {
    let mut requests = Vec::new();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "bad"));
    requests.push(metadata);
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "1S"));
    assert!(metadata.insert("grpc-timeout", "2S"));
    requests.push(metadata);
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-status", "0"));
    requests.push(metadata);
    for metadata in requests {
        let (io, probe) = fixture(Vec::new(), 16384, false);
        let result = NativeServerStream::new(&Cx::for_testing(), io, "localhost", "/test.Service/Watch",
            Request::with_metadata(Bytes::new(), metadata), IdentityCodec, NativeStreamConfig::default());
        assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
        assert!(probe.writes.lock().unwrap().is_empty());
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    let (io, _) = fixture(Vec::new(), 16384, false);
    let result = NativeServerStream::new(&Cx::for_testing(), io, "localhost", "/test.Service/Watch",
        Request::new(Bytes::new()), IdentityCodec,
        NativeStreamConfig { timeout: Some(Duration::from_secs(1)), ..NativeStreamConfig::default() });
    assert_eq!(result.unwrap_err().code(), Code::FailedPrecondition);
}

#[test]
fn explicit_cancel_and_whole_stream_drop_release_io_once_without_new_io() {
    let (io, probe) = fixture(Vec::new(), 16384, false);
    let mut stream = call(io);
    stream.cancel();
    stream.cancel();
    assert_eq!(stream.status().unwrap().code(), Code::Cancelled);
    assert!(run(stream.message()).unwrap().is_none());
    drop(stream);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert!(probe.writes.lock().unwrap().is_empty());
    let (io, probe) = fixture(Vec::new(), 16384, false);
    drop(call(io));
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(probe.read_calls.load(Ordering::SeqCst), 0);
}

#[test]
#[cfg(feature = "compression")]
fn gzip_stream_uses_the_existing_codec_and_enforces_decompressed_limit() {
    let compressed = crate::grpc::codec::gzip_frame_compress(Bytes::from(vec![b'a'; 1000])).unwrap();
    for limit in [2000, 100] {
        let mut bytes = frame(4, 0, &[]);
        bytes.extend(headers(&[(":status", "200"), ("content-type", "application/grpc"), ("grpc-encoding", "gzip")], false));
        let mut payload = vec![1];
        payload.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(&compressed);
        bytes.extend(frame(0, 0, &payload));
        bytes.extend(headers(&[("grpc-status", "0")], true));
        let (io, _) = fixture(bytes, 7, false);
        let mut stream = NativeServerStream::new(&Cx::for_testing(), io, "localhost", "/test.Service/Watch",
            Request::new(Bytes::new()), IdentityCodec,
            NativeStreamConfig { accept_gzip: true, max_recv_message_size: limit, ..NativeStreamConfig::default() }).unwrap();
        if limit == 2000 {
            assert_eq!(run(stream.message()).unwrap().unwrap().len(), 1000);
            assert!(run(stream.message()).unwrap().is_none());
        } else {
            assert_eq!(run(stream.message()).unwrap_err().code(), Code::ResourceExhausted);
        }
    }
}

mod native;

#[test]
fn immediately_ready_message_batches_yield_without_losing_the_next_item() {
    let mut bytes = start();
    let mut body = Vec::new();
    for _ in 0..33 { body.extend(message(b"")); }
    bytes.extend(frame(0, 0, &body));
    bytes.extend(headers(&[("grpc-status", "0")], true));
    let (io, _) = fixture(bytes, 16384, false);
    let mut stream = call(io);
    for _ in 0..32 { assert!(run(stream.message()).unwrap().unwrap().is_empty()); }
    let retained = stream.buffered_data_bytes();
    let mut task = Context::from_waker(Waker::noop());
    assert!(stream.poll_message(&mut task).is_pending());
    assert_eq!(stream.buffered_data_bytes(), retained);
    assert!(run(stream.message()).unwrap().unwrap().is_empty());
    assert!(run(stream.message()).unwrap().is_none());
}

#[test]
fn codec_setup_and_decode_use_the_explicit_context_not_an_unrelated_ambient_task() {
    struct ContextCodec(TaskId);
    impl Codec for ContextCodec {
        type Encode = Bytes;
        type Decode = Bytes;
        type Error = std::convert::Infallible;

        fn encode(&mut self, value: &Bytes) -> Result<Bytes, Self::Error> {
            assert_eq!(Cx::current().unwrap().task_id(), self.0);
            Ok(value.clone())
        }

        fn decode(&mut self, value: &Bytes) -> Result<Bytes, Self::Error> {
            assert_eq!(Cx::current().unwrap().task_id(), self.0);
            Ok(value.clone())
        }
    }
    let explicit = Cx::new_with_drivers(RegionId::new_for_test(1, 0), TaskId::new_for_test(42, 0),
        Budget::INFINITE, None, None, None, None, None);
    let unrelated = Cx::new_with_drivers(RegionId::new_for_test(1, 0), TaskId::new_for_test(43, 0),
        Budget::INFINITE, None, None, None, None, None);
    let _ambient = Cx::set_current(Some(unrelated.clone()));
    let mut bytes = start();
    bytes.extend(frame(0, 0, &message(b"ok")));
    bytes.extend(headers(&[("grpc-status", "0")], true));
    let (io, _) = fixture(bytes, 16384, false);
    let mut stream = NativeServerStream::new(&explicit, io, "localhost", "/test.Service/Watch",
        Request::new(Bytes::new()), ContextCodec(explicit.task_id()), NativeStreamConfig::default()).unwrap();
    assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"ok");
    assert!(run(stream.message()).unwrap().is_none());
    assert_eq!(Cx::current().unwrap().task_id(), unrelated.task_id());
}

mod duplex {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[derive(Default)]
    struct Gate {
        open: AtomicBool,
        blocked: AtomicUsize,
        waker: Mutex<Option<Waker>>,
    }

    impl Gate {
        fn park(&self, task: &Context<'_>) {
            *self.waker.lock().unwrap() = Some(task.waker().clone());
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }

        fn release(&self) {
            self.open.store(true, Ordering::SeqCst);
            let wake = self.waker.lock().unwrap().take();
            if let Some(wake) = wake { wake.wake(); }
        }
    }

    struct DuplexIo {
        inner: FixtureIo,
        gate: Arc<Gate>,
        prefix: usize,
        block_flush: bool,
        read_releases_write: bool,
    }

    impl AsyncRead for DuplexIo {
        fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let result = Pin::new(&mut this.inner).poll_read(task, buf);
            if buf.filled().len() > before && this.read_releases_write {
                this.gate.release();
            }
            result
        }
    }

    impl AsyncWrite for DuplexIo {
        fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if !this.block_flush && !this.gate.open.load(Ordering::SeqCst) {
                let written = this.inner.probe.writes.lock().unwrap().len();
                let available = this.prefix.saturating_sub(written).min(bytes.len());
                if available == 0 {
                    this.gate.park(task);
                    return Poll::Pending;
                }
                return Pin::new(&mut this.inner).poll_write(task, &bytes[..available]);
            }
            Pin::new(&mut this.inner).poll_write(task, bytes)
        }

        fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.block_flush && !this.gate.open.load(Ordering::SeqCst) {
                this.gate.park(task);
                return Poll::Pending;
            }
            Pin::new(&mut this.inner).poll_flush(task)
        }

        fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(task)
        }
    }

    fn gated(bytes: Vec<u8>, block_flush: bool, read_releases_write: bool) -> (DuplexIo, Arc<Probe>, Arc<Gate>) {
        let (inner, probe) = fixture(bytes, FRAME_BYTES, false);
        let gate = Arc::new(Gate::default());
        (DuplexIo {
            inner, gate: Arc::clone(&gate), prefix: 3, block_flush, read_releases_write,
        }, probe, gate)
    }

    fn duplex_call(io: DuplexIo) -> NativeServerStream<DuplexIo, IdentityCodec> {
        NativeServerStream::new(&Cx::for_testing(), io, "localhost", "/test.Service/Watch",
            Request::new(Bytes::from_static(b"request-once")), IdentityCodec,
            NativeStreamConfig::default()).unwrap()
    }

    fn success() -> Vec<u8> {
        let mut bytes = start();
        bytes.extend(frame(0, 0, &message(b"duplex-response")));
        bytes.extend(headers(&[("grpc-status", "0")], true));
        bytes
    }

    fn ping() -> Vec<u8> {
        let mut bytes = frame(6, 0, b"duplex!!");
        bytes[5..9].copy_from_slice(&0_u32.to_be_bytes());
        bytes
    }

    #[test]
    fn blocked_write_and_flush_read_the_peer_without_replaying_request_bytes() {
        let bytes = success();
        let (ordinary, expected) = fixture(bytes.clone(), FRAME_BYTES, false);
        let mut ordinary = call(ordinary);
        assert_eq!(run(ordinary.message()).unwrap().unwrap().as_ref(), b"duplex-response");
        assert!(run(ordinary.message()).unwrap().is_none());
        for block_flush in [false, true] {
            let (io, probe, gate) = gated(bytes.clone(), block_flush, true);
            let mut stream = duplex_call(io);
            assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"duplex-response");
            assert!(gate.blocked.load(Ordering::SeqCst) > 0, "must first reach real fixture Pending");
            assert!(gate.open.load(Ordering::SeqCst), "reading is the only gate release");
            assert!(run(stream.message()).unwrap().is_none());
            assert_eq!(stream.status().unwrap().code(), Code::Ok);
            assert_eq!(*probe.writes.lock().unwrap(), *expected.writes.lock().unwrap());
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn interrupted_duplex_header_wait_keeps_both_partial_directions() {
        let bytes = success();
        let (ordinary, expected) = fixture(bytes.clone(), FRAME_BYTES, false);
        let mut ordinary = call(ordinary);
        assert!(run(ordinary.message()).unwrap().is_some());
        assert!(run(ordinary.message()).unwrap().is_none());
        let (io, probe, gate) = gated(bytes, false, true);
        probe.readable.store(3, Ordering::SeqCst); // Partial peer SETTINGS header.
        let mut stream = duplex_call(io);
        {
            let mut wait = Box::pin(stream.headers());
            assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert!(gate.blocked.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.position.load(Ordering::SeqCst), 3, "read even while write is parked");
        assert_eq!(probe.writes.lock().unwrap().len(), 3, "partial preface retained");
        probe.readable.store(usize::MAX, Ordering::SeqCst);
        assert!(run(stream.headers()).unwrap().get("x-initial").is_some());
        assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"duplex-response");
        assert!(run(stream.message()).unwrap().is_none());
        assert_eq!(*probe.writes.lock().unwrap(), *expected.writes.lock().unwrap());
    }

    #[test]
    fn early_status_and_reset_retire_a_call_even_when_writes_never_resume() {
        for reset in [false, true] {
            let mut bytes = frame(4, 0, &[]);
            let expected = if reset {
                bytes.extend(frame(3, 0, &8_u32.to_be_bytes()));
                Code::Cancelled
            } else {
                bytes.extend(headers(&[(":status", "200"), ("content-type", "application/grpc"),
                    ("grpc-status", "7"), ("grpc-message", "refused")], true));
                Code::PermissionDenied
            };
            let (io, probe, gate) = gated(bytes, false, false);
            let mut stream = duplex_call(io);
            let error = run(stream.message()).unwrap_err();
            assert_eq!(error.code(), expected);
            if !reset { assert_eq!(error.message(), "refused"); }
            assert!(!gate.open.load(Ordering::SeqCst));
            assert!(gate.blocked.load(Ordering::SeqCst) > 0);
            assert_eq!(probe.writes.lock().unwrap().len(), 3);
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
            assert!(stream.connection.is_none());
            assert!(stream.outbound.is_empty());
            assert_eq!(stream.status().unwrap().code(), expected);
            assert!(run(stream.message()).unwrap().is_none());
        }
    }

    #[test]
    fn blocked_writer_caps_control_replies_across_waits_and_resumes_on_write_wake() {
        let mut bytes = start();
        for _ in 0..MAX_UNFLUSHED_READ_FRAMES * 3 { bytes.extend(ping()); }
        bytes.extend(frame(0, 0, &message(b"resumed")));
        bytes.extend(headers(&[("grpc-status", "0")], true));
        let (io, probe, gate) = gated(bytes, false, false);
        let mut stream = duplex_call(io);
        assert!(run(stream.headers()).unwrap().get("x-initial").is_some());
        let mut task = Context::from_waker(Waker::noop());
        // Repeatedly drop and recreate the borrowing wait: the quota belongs
        // to the call, not the temporary wait, so this cannot renew admission.
        for _ in 0..4 {
            let mut wait = Box::pin(stream.message());
            assert!(wait.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(stream.unflushed_read_frames, MAX_UNFLUSHED_READ_FRAMES);
        let reads = probe.read_calls.load(Ordering::SeqCst);
        let received = probe.position.load(Ordering::SeqCst);
        assert!(stream.inbound.len() <= 2 * FRAME_BYTES);
        for _ in 0..8 { assert!(stream.poll_message(&mut task).is_pending()); }
        assert_eq!(probe.read_calls.load(Ordering::SeqCst), reads);
        assert_eq!(probe.position.load(Ordering::SeqCst), received);
        assert_eq!(stream.unflushed_read_frames, MAX_UNFLUSHED_READ_FRAMES);
        assert!(gate.waker.lock().unwrap().is_some(), "writer owns the pending wake");
        gate.release();
        assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"resumed");
        assert!(run(stream.message()).unwrap().is_none());
        assert_eq!(stream.status().unwrap().code(), Code::Ok);
        assert_eq!(stream.unflushed_read_frames, 0);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_and_deadline_still_retire_a_call_at_the_control_reply_limit() {
        for cancel in [false, true] {
            let mut bytes = frame(4, 0, &[]);
            for _ in 0..MAX_UNFLUSHED_READ_FRAMES * 2 { bytes.extend(ping()); }
            let (io, probe, _) = gated(bytes, false, false);
            let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
            let cx = timed_cx(&clock);
            let mut stream = NativeServerStream::new(&cx, io, "localhost", "/test.Service/Watch",
                Request::new(Bytes::new()), IdentityCodec,
                NativeStreamConfig { timeout: Some(Duration::from_secs(2)), ..NativeStreamConfig::default() }).unwrap();
            let mut task = Context::from_waker(Waker::noop());
            for _ in 0..4 { assert!(stream.poll_headers(&mut task).is_pending()); }
            assert_eq!(stream.unflushed_read_frames, MAX_UNFLUSHED_READ_FRAMES);
            let expected = if cancel {
                cx.cancel_with(CancelKind::User, Some("parked duplex cancellation"));
                Code::Cancelled
            } else {
                clock.advance_to(Time::from_secs(22));
                Code::DeadlineExceeded
            };
            assert!(matches!(stream.poll_message(&mut task),
                Poll::Ready(Some(Err(status))) if status.code() == expected));
            assert_eq!(stream.status().unwrap().code(), expected);
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
            assert_eq!(cx.is_cancel_requested(), cancel);
            assert!(stream.io.is_none() && stream.connection.is_none());
        }
    }
}
