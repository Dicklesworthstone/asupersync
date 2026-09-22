//! Fixed wire fixtures supplement (not replace) native-runtime integration.
//! br-asupersync-server-stack-hardening-eeexl1.10.

use super::*;
use crate::grpc::codec::IdentityCodec;
use crate::time::VirtualClock;
use crate::types::{Budget, RegionId, TaskId};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

#[derive(Default)]
struct Wire {
    input: Mutex<VecDeque<u8>>,
    output: Mutex<Vec<u8>>,
    reader: Mutex<Option<Waker>>,
    writer: Mutex<Option<Waker>>,
    eof: AtomicBool,
    write_credit: AtomicUsize,
    reads: AtomicUsize,
    drops: AtomicUsize,
}

impl Wire {
    fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            input: Mutex::new(bytes.into()),
            write_credit: AtomicUsize::new(usize::MAX),
            ..Self::default()
        })
    }

    fn append(&self, bytes: &[u8]) {
        self.input.lock().unwrap().extend(bytes);
        let wake = self.reader.lock().unwrap().take();
        if let Some(wake) = wake { wake.wake(); }
    }

    fn allow_writes(&self) {
        self.write_credit.store(usize::MAX, Ordering::SeqCst);
        let wake = self.writer.lock().unwrap().take();
        if let Some(wake) = wake { wake.wake(); }
    }
}

struct ScriptIo(Arc<Wire>);
impl Drop for ScriptIo {
    fn drop(&mut self) { self.0.drops.fetch_add(1, Ordering::SeqCst); }
}
impl AsyncRead for ScriptIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        let mut input = self.0.input.lock().unwrap();
        if input.is_empty() && !self.0.eof.load(Ordering::SeqCst) {
            *self.0.reader.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while buf.remaining() > 0 {
            let Some(byte) = input.pop_front() else { break; };
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ScriptIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let credit = self.0.write_credit.load(Ordering::SeqCst);
        if credit == 0 {
            *self.0.writer.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = bytes.len().min(credit);
        self.0.output.lock().unwrap().extend_from_slice(&bytes[..n]);
        self.0.write_credit.fetch_sub(n, Ordering::SeqCst);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

#[derive(Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn complete<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut task = Context::from_waker(Waker::noop());
    // Only immediate fixed-fixture I/O: bounded polling accommodates the
    // production cooperative yield, never substitutes for a native wake test.
    for _ in 0..128 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut task) { return value; }
    }
    panic!("fixture unexpectedly parked");
}

fn context(clock: &Arc<VirtualClock>) -> Cx {
    Cx::new_with_drivers(
        RegionId::new_for_test(1, 0), TaskId::new_for_test(1, 0), Budget::INFINITE,
        None, None, None, Some(TimerDriverHandle::with_virtual_clock(Arc::clone(clock))), None,
    )
}

fn channel() -> Channel { complete(Channel::connect("http://localhost:50051")).unwrap() }

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn header_block(pairs: &[(&str, &str)], end: bool) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in pairs {
        assert!(name.len() < 128 && value.len() < 128);
        block.extend_from_slice(&[0, u8::try_from(name.len()).unwrap()]);
        block.extend_from_slice(name.as_bytes());
        block.push(u8::try_from(value.len()).unwrap());
        block.extend_from_slice(value.as_bytes());
    }
    frame(1, 4 | u8::from(end), 1, &block)
}

fn initial() -> Vec<u8> {
    let mut bytes = frame(4, 0, 0, &[]);
    bytes.extend(header_block(&[(":status", "200"), ("content-type", "application/grpc"), ("x-origin", "initial")], false));
    bytes
}

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

type Client = NativeServerStream<ScriptIo, IdentityCodec>;

fn open(wire: &Arc<Wire>, cx: &Cx) -> Client {
    complete(channel().server_streaming_on(
        cx, ScriptIo(Arc::clone(wire)), "/test.Service/Watch", Request::new(Bytes::new()), IdentityCodec,
    )).unwrap()
}

#[test]
fn native_pull_messages_preserve_separate_metadata_and_terminal_details() {
    let wire = Wire::new(initial());
    let cx = context(&Arc::new(VirtualClock::new()));
    let mut client = open(&wire, &cx);
    let mut data = envelope(b"first");
    data.extend(envelope(b"second"));
    wire.append(&frame(0, 0, 1, &data));
    wire.append(&header_block(&[("grpc-status", "3"), ("grpc-message", "bad%20%25"),
        ("grpc-status-details-bin", "AP8="), ("x-origin", "trailing"), ("x-bin", "AQ==,Ag")], true));
    assert_eq!(complete(client.message()).unwrap().unwrap().as_ref(), b"first");
    let reads = wire.reads.load(Ordering::SeqCst);
    assert_eq!(complete(client.message()).unwrap().unwrap().as_ref(), b"second");
    assert_eq!(wire.reads.load(Ordering::SeqCst), reads, "buffered message needs no read-ahead");
    let status = complete(client.message()).unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "bad %");
    assert_eq!(status.details().unwrap().as_ref(), &[0, 255]);
    assert!(matches!(client.initial_metadata().get("x-origin"), Some(MetadataValue::Ascii(v)) if v == "initial"));
    let trailers = client.trailing_metadata().unwrap();
    assert!(matches!(trailers.get("x-origin"), Some(MetadataValue::Ascii(v)) if v == "trailing"));
    assert_eq!(trailers.iter().filter(|(key, _)| *key == "x-bin").count(), 2);
    assert!(complete(client.message()).unwrap().is_none());
    assert_eq!(client.terminal_status().unwrap().code(), Code::InvalidArgument);
    assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn interrupted_message_wait_preserves_fragment_and_unregisters_on_drop() {
    let wire = Wire::new(initial());
    let cx = context(&Arc::new(VirtualClock::new()));
    let mut client = open(&wire, &cx);
    let bytes = envelope(b"fragmented");
    wire.append(&frame(0, 0, 1, &bytes[..7]));
    let count = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut wait = Box::pin(client.message());
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    let written = wire.output.lock().unwrap().clone();
    wire.append(&frame(0, 0, 1, &bytes[7..]));
    wire.append(&header_block(&[("grpc-status", "0")], true));
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(complete(client.message()).unwrap().unwrap().as_ref(), b"fragmented");
    assert!(complete(client.message()).unwrap().is_none());
    assert!(wire.output.lock().unwrap().starts_with(&written));
    assert_eq!(wire.output.lock().unwrap().windows(CLIENT_PREFACE.len()).filter(|bytes| *bytes == &CLIENT_PREFACE[..]).count(), 1);
    assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn partial_transport_write_resumes_without_replaying_committed_prefix() {
    let wire = Wire::new(initial());
    wire.write_credit.store(5, Ordering::SeqCst);
    let cx = context(&Arc::new(VirtualClock::new()));
    let mut client = open(&wire, &cx);
    assert_eq!(&*wire.output.lock().unwrap(), &CLIENT_PREFACE[..5]);
    {
        let mut wait = Box::pin(client.message());
        assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    wire.allow_writes();
    wire.append(&frame(0, 0, 1, &envelope(b"resumed")));
    wire.append(&header_block(&[("grpc-status", "0")], true));
    assert_eq!(complete(client.message()).unwrap().unwrap().as_ref(), b"resumed");
    assert!(complete(client.message()).unwrap().is_none());
    let output = wire.output.lock().unwrap();
    assert!(output.starts_with(CLIENT_PREFACE));
    assert_eq!(output.windows(CLIENT_PREFACE.len()).filter(|bytes| *bytes == &CLIENT_PREFACE[..]).count(), 1);
}

#[test]
fn missing_status_truncation_and_early_eof_never_become_ok() {
    for (tail, eof, expected) in [
        (frame(0, 1, 1, &[]), false, Code::Internal),
        (frame(0, 1, 1, &[0, 0, 0, 0, 3, 1]), false, Code::Internal),
        (Vec::new(), true, Code::Unavailable),
    ] {
        let wire = Wire::new(initial());
        let mut client = open(&wire, &context(&Arc::new(VirtualClock::new())));
        wire.append(&tail);
        wire.eof.store(eof, Ordering::SeqCst);
        assert_eq!(complete(client.message()).unwrap_err().code(), expected);
        assert!(complete(client.message()).unwrap().is_none());
        assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn oversized_declared_message_fails_before_its_payload_arrives() {
    let wire = Wire::new(initial());
    let cx = context(&Arc::new(VirtualClock::new()));
    let channel = complete(Channel::builder("http://localhost:50051").max_recv_message_size(2).connect()).unwrap();
    let mut client = complete(channel.server_streaming_on(&cx, ScriptIo(Arc::clone(&wire)), "/s/M", Request::new(Bytes::new()), IdentityCodec)).unwrap();
    wire.append(&frame(0, 0, 1, &[0, 0, 0, 0, 3]));
    assert_eq!(complete(client.message()).unwrap_err().code(), Code::ResourceExhausted);
    assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn headers_only_success_and_failure_do_not_invent_a_message() {
    for code in ["0", "16"] {
        let mut bytes = frame(4, 0, 0, &[]);
        bytes.extend(header_block(&[(":status", "200"), ("content-type", "application/grpc"), ("grpc-status", code)], true));
        let wire = Wire::new(bytes);
        let mut client = open(&wire, &context(&Arc::new(VirtualClock::new())));
        let result = complete(client.message());
        if code == "0" { assert!(result.unwrap().is_none()); }
        else { assert_eq!(result.unwrap_err().code(), Code::Unauthenticated); }
        assert!(complete(client.message()).unwrap().is_none());
    }
}

#[test]
fn malformed_and_unnegotiated_response_headers_fail_closed() {
    for extra in [
        vec![("content-type", "application/grpc-web")],
        vec![("content-type", "application/grpc"), ("grpc-encoding", "gzip")],
        vec![("content-type", "application/grpc"), ("grpc-status", "0")],
        vec![("content-type", "application/grpc"), ("content-type", "application/grpc")],
    ] {
        let mut headers = vec![(":status", "200")];
        headers.extend(extra);
        let mut bytes = frame(4, 0, 0, &[]);
        bytes.extend(header_block(&headers, false));
        let wire = Wire::new(bytes);
        let cx = context(&Arc::new(VirtualClock::new()));
        let result = complete(channel().server_streaming_on(&cx, ScriptIo(Arc::clone(&wire)), "/s/M", Request::new(Bytes::new()), IdentityCodec));
        assert!(result.is_err());
        assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn cancellation_wakes_a_parked_read_and_preserves_attribution() {
    for (cause, code) in [(CancelKind::User, Code::Cancelled), (CancelKind::Deadline, Code::DeadlineExceeded), (CancelKind::CostBudget, Code::ResourceExhausted)] {
        let wire = Wire::new(initial());
        let cx = context(&Arc::new(VirtualClock::new()));
        let mut client = open(&wire, &cx);
        let count = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut wait = Box::pin(client.message());
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        cx.cancel_with(cause, Some("fixture cancellation"));
        assert!(count.0.load(Ordering::SeqCst) > 0, "no I/O event was injected");
        assert!(matches!(wait.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Err(status)) if status.code() == code));
        drop(wait);
        assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
        assert!(complete(client.message()).unwrap().is_none());
    }
}

#[test]
fn absolute_deadline_is_not_restarted_by_message_or_unrelated_ambient_clock() {
    let clock = Arc::new(VirtualClock::new());
    let cx = context(&clock);
    let wire = Wire::new(initial());
    let channel = complete(Channel::builder("http://localhost:50051").timeout(Duration::from_secs(2)).connect()).unwrap();
    let mut client = complete(channel.server_streaming_on(&cx, ScriptIo(Arc::clone(&wire)), "/s/M", Request::new(Bytes::new()), IdentityCodec)).unwrap();
    clock.advance_to(Time::from_secs(1));
    wire.append(&frame(0, 0, 1, &envelope(b"one")));
    assert_eq!(complete(client.message()).unwrap().unwrap().as_ref(), b"one");
    let unrelated = context(&Arc::new(VirtualClock::starting_at(Time::from_secs(999))));
    let _guard = Cx::set_current(Some(unrelated));
    clock.advance_to(Time::from_secs(2));
    wire.append(&frame(0, 0, 1, &envelope(b"too late")));
    assert_eq!(complete(client.message()).unwrap_err().code(), Code::DeadlineExceeded);
    assert!(!cx.is_cancel_requested(), "local call timeout must not cancel caller");
}

#[test]
fn header_timeout_does_not_limit_an_unbounded_stream_after_headers() {
    let clock = Arc::new(VirtualClock::new());
    let cx = context(&clock);
    let wire = Wire::new(initial());
    let mut client = open(&wire, &cx);
    assert!(client.header_timer.is_none());
    clock.advance_to(Time::from_secs(600));
    wire.append(&frame(0, 0, 1, &envelope(b"still alive")));
    assert_eq!(complete(client.message()).unwrap().unwrap().as_ref(), b"still alive");
    client.cancel();
    assert_eq!(wire.drops.load(Ordering::SeqCst), 1);
    assert_eq!(client.terminal_status().unwrap().code(), Code::Cancelled);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn path_metadata_and_window_admission_happen_before_any_transport_write() {
    let cx = context(&Arc::new(VirtualClock::new()));
    for path in ["missing", "/s", "/s/M/extra", "/s/M?query"] {
        let wire = Wire::new(Vec::new());
        assert!(complete(channel().server_streaming_on(&cx, ScriptIo(Arc::clone(&wire)), path, Request::new(Bytes::new()), IdentityCodec)).is_err());
        assert!(wire.output.lock().unwrap().is_empty());
    }
    for name in ["content-length", "grpc-status", "authorization"] {
        let wire = Wire::new(initial());
        let mut request = Request::new(Bytes::new());
        assert!(request.metadata_mut().insert(name, "private"));
        let result = complete(channel().server_streaming_on(&cx, ScriptIo(Arc::clone(&wire)), "/s/M", request, IdentityCodec));
        if name == "authorization" {
            let client = result.unwrap();
            assert!(!format!("{client:?}").contains("private"));
        } else {
            assert!(result.is_err());
            assert!(wire.output.lock().unwrap().is_empty());
        }
    }
    let mut config = ChannelConfig::default();
    config.initial_stream_window_size = 0;
    assert!(validate_config(&config).is_err());
    config.initial_stream_window_size = u32::MAX;
    assert!(validate_config(&config).is_err());
}

#[test]
fn deadline_meets_channel_request_and_parent_without_using_connect_timeout() {
    let cx = context(&Arc::new(VirtualClock::new()));
    let mut metadata = Metadata::new();
    let mut config = ChannelConfig::default();
    assert_eq!(call_deadline(&cx, &metadata, &config, Time::ZERO).unwrap(), None);
    config.timeout = Some(Duration::from_secs(4));
    assert!(metadata.insert("grpc-timeout", "9S"));
    assert_eq!(call_deadline(&cx, &metadata, &config, Time::ZERO).unwrap(), Some(Time::from_secs(4)));
    assert!(metadata.insert("grpc-timeout", "1S"));
    assert_eq!(call_deadline(&cx, &metadata, &config, Time::ZERO).unwrap_err().code(), Code::InvalidArgument);
}
