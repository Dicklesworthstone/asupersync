use super::*;
use crate::io::ReadBuf;
use crate::security::{AuthenticationTag, SecurityContext};
use crate::transport::{SymbolSinkExt, SymbolStreamExt};
use crate::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct WriteState {
    bytes: Vec<u8>,
    allowance: usize,
    chunk: usize,
    calls: usize,
    shutdowns: usize,
    shutdown_blocked: bool,
    failure: bool,
    panic_after_write: bool,
    waiter: Option<Waker>,
}

#[derive(Clone)]
struct Writer(Arc<Mutex<WriteState>>);

impl Writer {
    fn new(chunk: usize, allowance: usize) -> Self {
        Self(Arc::new(Mutex::new(WriteState {
            bytes: Vec::new(), allowance, chunk, calls: 0, shutdowns: 0,
            shutdown_blocked: false, failure: false, panic_after_write: false, waiter: None,
        })))
    }

    fn release(&self, allowance: usize) {
        let waiter = {
            let mut state = self.0.lock().unwrap();
            state.allowance = allowance;
            state.waiter.take()
        };
        if let Some(waiter) = waiter { waiter.wake(); }
    }

    fn bytes(&self) -> Vec<u8> { self.0.lock().unwrap().bytes.clone() }
}

impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        if state.failure { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        if state.allowance == 0 {
            state.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = bytes.len().min(state.chunk).min(state.allowance);
        state.bytes.extend_from_slice(&bytes[..n]);
        state.allowance -= n;
        let panic_after_write = state.panic_after_write;
        drop(state);
        assert!(!panic_after_write, "fixture panicked after accepting an unknown write prefix");
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.shutdowns += 1;
        if state.shutdown_blocked {
            state.waiter = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

struct ReadState {
    bytes: Vec<u8>,
    cursor: usize,
    allowance: usize,
    chunk: usize,
    calls: usize,
    panic_after_read: bool,
    waiter: Option<Waker>,
}

#[derive(Clone)]
struct Reader(Arc<Mutex<ReadState>>);

impl Reader {
    fn new(bytes: Vec<u8>, chunk: usize, allowance: usize) -> Self {
        Self(Arc::new(Mutex::new(ReadState {
            bytes, cursor: 0, allowance, chunk, calls: 0, panic_after_read: false, waiter: None,
        })))
    }

    fn release(&self, allowance: usize) {
        let waiter = {
            let mut state = self.0.lock().unwrap();
            state.allowance = allowance;
            state.waiter.take()
        };
        if let Some(waiter) = waiter { waiter.wake(); }
    }
}

impl AsyncRead for Reader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        if state.cursor == state.bytes.len() { return Poll::Ready(Ok(())); }
        if state.allowance == 0 {
            state.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = (state.bytes.len() - state.cursor).min(state.chunk).min(state.allowance).min(buf.remaining());
        buf.put_slice(&state.bytes[state.cursor..state.cursor + n]);
        state.cursor += n;
        state.allowance -= n;
        let panic_after_read = state.panic_after_read;
        drop(state);
        assert!(!panic_after_read, "fixture panicked after consuming an unknown read prefix");
        Poll::Ready(Ok(()))
    }
}

fn symbol(esi: u32, data: &[u8]) -> AuthenticatedSymbol {
    let raw = Symbol::new(SymbolId::new(ObjectId::new(7, 11), 0, esi), data.to_vec(), SymbolKind::Source);
    SecurityContext::new(AuthKey::from_seed(42)).sign_symbol(&raw)
}

fn wire(symbols: &[AuthenticatedSymbol]) -> Vec<u8> {
    let encoded = encode_symbol_batch(symbols, SymbolBatchLimits {
        max_encoded_bytes: 1 << 20, max_symbols: 100,
        max_payload_bytes: 1 << 20, max_decoded_bytes: 1 << 20,
    }).unwrap();
    let mut bytes = (encoded.as_ref().len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(encoded.as_ref());
    bytes
}

fn ready<T>(cx: &mut Context<'_>, mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
    for _ in 0..1024 {
        if let Poll::Ready(value) = poll(cx) { return value; }
    }
    panic!("ready fixture did not finish within the bounded poll budget");
}

#[test]
fn exact_wire_limits_and_local_admission_do_not_poison_a_usable_sink() {
    assert!(SymbolFrameLimits::new(0).is_err());
    assert!(SymbolFrameLimits::new(usize::MAX).is_err());
    let limits = SymbolFrameLimits::new(5).unwrap();
    assert_eq!(limits.max_wire_bytes(), 4 + 32 + 42 + 5);
    let writer = Writer::new(usize::MAX, usize::MAX);
    let mut sink = FramedSymbolSink::new(writer.clone(), limits);
    let mut cx = Context::from_waker(Waker::noop());
    let accepted = symbol(0, b"hello");
    let sentinel = AuthenticatedSymbol::from_parts(accepted.symbol().clone(), AuthenticationTag::zero());
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, sentinel), Poll::Ready(Err(SinkError::SendFailed { .. }))));
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, symbol(1, b"too big")), Poll::Ready(Err(SinkError::SendFailed { .. }))));
    assert!(writer.bytes().is_empty());
    assert_eq!(sink.buffered_bytes(), 0);
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, accepted.clone()), Poll::Ready(Ok(()))));
    assert_eq!(sink.buffered_bytes(), limits.max_wire_bytes());
    assert!(writer.bytes().is_empty(), "send acceptance stages a frame");
    ready(&mut cx, |cx| Pin::new(&mut sink).poll_flush(cx)).unwrap();
    assert_eq!(writer.bytes(), wire(&[accepted]));
    assert_eq!(&writer.bytes()[..16], b"\0\0\0OASUPSYM\0\x01\0\0\0");
    assert!(!format!("{sink:?}").contains("hello"));
}

#[test]
fn pending_send_and_dropped_flush_preserve_one_accepted_frame_without_replay() {
    let writer = Writer::new(1, 5);
    let mut sink = FramedSymbolSink::new(writer.clone(), SymbolFrameLimits::new(64).unwrap());
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let first = symbol(0, b"first payload");
    let second = symbol(1, b"second payload");
    let first_wire = wire(std::slice::from_ref(&first));
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, first), Poll::Ready(Ok(()))));
    {
        let mut sending = Box::pin(sink.send(second.clone()));
        assert!(sending.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(writer.bytes(), first_wire[..5]);
    assert_eq!(sink.buffered_bytes(), first_wire.len() - 5);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0, "blocked I/O must not busy wake");
    writer.release(usize::MAX);
    assert_eq!(counter.0.load(Ordering::SeqCst), 1, "transport readiness wakes the parked wait");
    let calls = writer.0.lock().unwrap().calls;
    {
        let mut flushing = Box::pin(sink.flush());
        assert!(flushing.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(writer.0.lock().unwrap().calls - calls, 32, "one-byte writes yield after the framed I/O budget");
    ready(&mut cx, |cx| Pin::new(&mut sink).poll_flush(cx)).unwrap();
    assert_eq!(writer.bytes(), first_wire, "dropping the borrowing flush did not replay its prefix");
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, second.clone()), Poll::Ready(Ok(()))));
    ready(&mut cx, |cx| Pin::new(&mut sink).poll_close(cx)).unwrap();
    let mut expected = first_wire;
    expected.extend(wire(&[second]));
    assert_eq!(writer.bytes(), expected, "the pending second send had not been accepted");
    assert_eq!(sink.buffered_bytes(), 0);
}

#[test]
fn started_close_is_sticky_across_drop_and_transport_failure_is_terminal() {
    let writer = Writer::new(7, usize::MAX);
    writer.0.lock().unwrap().shutdown_blocked = true;
    let mut sink = FramedSymbolSink::new(writer.clone(), SymbolFrameLimits::default());
    let mut cx = Context::from_waker(Waker::noop());
    let first = symbol(0, b"close after this");
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, first.clone()), Poll::Ready(Ok(()))));
    {
        let mut closing = Box::pin(sink.close());
        assert!(closing.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(writer.bytes(), wire(&[first]));
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, symbol(1, b"refused")), Poll::Ready(Err(SinkError::Closed))));
    assert!(matches!(Pin::new(&mut sink).poll_ready(&mut cx), Poll::Ready(Err(SinkError::Closed))));
    writer.0.lock().unwrap().shutdown_blocked = false;
    writer.release(usize::MAX);
    ready(&mut cx, |cx| Pin::new(&mut sink).poll_close(cx)).unwrap();
    let shutdowns = writer.0.lock().unwrap().shutdowns;
    ready(&mut cx, |cx| Pin::new(&mut sink).poll_close(cx)).unwrap();
    assert_eq!(writer.0.lock().unwrap().shutdowns, shutdowns, "completed close is idempotent");

    let broken = Writer::new(3, 9);
    let mut sink = FramedSymbolSink::new(broken.clone(), SymbolFrameLimits::default());
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, symbol(0, b"partial")), Poll::Ready(Ok(()))));
    assert!(Pin::new(&mut sink).poll_flush(&mut cx).is_pending());
    broken.0.lock().unwrap().failure = true;
    assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Err(SinkError::Io { source })) if source.kind() == io::ErrorKind::BrokenPipe));
    let calls = broken.0.lock().unwrap().calls;
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, symbol(1, b"no retry")), Poll::Ready(Err(SinkError::Closed))));
    assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Err(SinkError::Closed))));
    assert!(matches!(Pin::new(&mut sink).poll_close(&mut cx), Poll::Ready(Err(SinkError::Closed))));
    assert_eq!(broken.0.lock().unwrap().calls, calls, "failed transport cannot emit a second frame");
}

#[test]
fn dropped_receive_retains_fragmented_frame_and_reverifies_every_symbol() {
    let first = symbol(0, b"secret-one");
    let second = symbol(1, b"secret-two");
    let mut bytes = wire(std::slice::from_ref(&first));
    bytes.extend(wire(std::slice::from_ref(&second)));
    let reader = Reader::new(bytes, 1, 11);
    let mut stream = FramedSymbolStream::new(reader.clone(), AuthKey::from_seed(42), SymbolFrameLimits::new(32).unwrap());
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let mut next = Box::pin(stream.next());
        assert!(next.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(stream.buffered_bytes(), 11);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    reader.release(usize::MAX);
    let calls = reader.0.lock().unwrap().calls;
    assert!(Pin::new(&mut stream).poll_next(&mut cx).is_pending());
    assert_eq!(reader.0.lock().unwrap().calls - calls, 32, "ready one-byte reads cooperate");
    for expected in [first, second] {
        let actual = ready(&mut cx, |cx| Pin::new(&mut stream).poll_next(cx)).unwrap().unwrap();
        assert_eq!(actual.symbol(), expected.symbol());
        assert_eq!(actual.tag(), expected.tag());
        assert!(actual.is_verified());
    }
    assert!(ready(&mut cx, |cx| Pin::new(&mut stream).poll_next(cx)).is_none());
    assert!(stream.is_exhausted());
    assert_eq!(stream.size_hint(), (0, Some(0)));
    assert!(!format!("{stream:?}").contains("secret"));
}

#[test]
fn hostile_frame_authentication_and_framing_errors_refuse_following_valid_data() {
    let valid = symbol(0, b"good");
    let raw = wire(std::slice::from_ref(&valid));
    let mut tampered = raw.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let sentinel = AuthenticatedSymbol::from_parts(valid.symbol().clone(), AuthenticationTag::zero());
    let mut wrong_magic = raw.clone();
    wrong_magic[4] ^= 1;
    let cases = [
        ("wrong key", raw.clone(), AuthKey::from_seed(7), true),
        ("tampered payload", tampered, AuthKey::from_seed(42), true),
        ("missing authentication", wire(&[sentinel]), AuthKey::from_seed(42), true),
        ("multiple symbols", wire(&[valid.clone(), symbol(1, b"more")]), AuthKey::from_seed(42), false),
        ("wrong magic", wrong_magic, AuthKey::from_seed(42), false),
        ("empty frame", vec![0, 0, 0, 0], AuthKey::from_seed(42), false),
    ];
    for (name, mut bytes, key, auth_error) in cases {
        bytes.extend_from_slice(&raw);
        let reader = Reader::new(bytes, usize::MAX, usize::MAX);
        let mut stream = FramedSymbolStream::new(reader, key, SymbolFrameLimits::new(64).unwrap());
        let mut cx = Context::from_waker(Waker::noop());
        let error = ready(&mut cx, |cx| Pin::new(&mut stream).poll_next(cx)).unwrap().unwrap_err();
        assert_eq!(matches!(&error, StreamError::AuthenticationFailed { .. }), auth_error, "{name}: {error}");
        assert!(stream.is_exhausted(), "{name}");
        assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None)), "{name}");
    }
}

#[test]
fn declared_oversize_and_truncated_frames_are_terminal_without_unbounded_reads() {
    let limits = SymbolFrameLimits::new(8).unwrap();
    let advertised = (limits.max_wire_bytes() as u32).to_be_bytes().to_vec();
    let reader = Reader::new(advertised, 4, 4);
    let mut stream = FramedSymbolStream::new(reader.clone(), AuthKey::from_seed(42), limits);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(Some(Err(StreamError::Io { source }))) if source.kind() == io::ErrorKind::InvalidData));
    assert_eq!(reader.0.lock().unwrap().cursor, 4, "refuse the prefix without reading a body");
    assert!(stream.is_exhausted());
    let full = wire(&[symbol(0, b"abc")]);
    for truncated in [full[..2].to_vec(), full[..full.len() - 1].to_vec()] {
        let reader = Reader::new(truncated, usize::MAX, usize::MAX);
        let mut stream = FramedSymbolStream::new(reader, AuthKey::from_seed(42), limits);
        assert!(matches!(ready(&mut cx, |cx| Pin::new(&mut stream).poll_next(cx)), Some(Err(StreamError::Io { source })) if source.kind() == io::ErrorKind::UnexpectedEof));
        assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None)));
    }
}

#[test]
fn caught_transport_panics_cannot_replay_unknown_partial_io() {
    let mut cx = Context::from_waker(Waker::noop());
    let writer = Writer::new(3, usize::MAX);
    writer.0.lock().unwrap().panic_after_write = true;
    let mut sink = FramedSymbolSink::new(writer.clone(), SymbolFrameLimits::default());
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, symbol(0, b"panic")), Poll::Ready(Ok(()))));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Pin::new(&mut sink).poll_flush(&mut cx);
    })).is_err());
    writer.0.lock().unwrap().panic_after_write = false;
    assert_eq!(writer.bytes().len(), 3);
    assert!(matches!(Pin::new(&mut sink).poll_send(&mut cx, symbol(1, b"refused")), Poll::Ready(Err(SinkError::Closed))));
    assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Err(SinkError::Closed))));
    assert_eq!(writer.bytes().len(), 3);

    let reader = Reader::new(wire(&[symbol(0, b"panic")]), 3, usize::MAX);
    reader.0.lock().unwrap().panic_after_read = true;
    let mut stream = FramedSymbolStream::new(reader.clone(), AuthKey::from_seed(42), SymbolFrameLimits::default());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Pin::new(&mut stream).poll_next(&mut cx);
    })).is_err());
    reader.0.lock().unwrap().panic_after_read = false;
    let calls = reader.0.lock().unwrap().calls;
    assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None)));
    assert_eq!(reader.0.lock().unwrap().calls, calls);
}

#[cfg(not(target_arch = "wasm32"))]
#[path = "native_tests.rs"]
mod native;
