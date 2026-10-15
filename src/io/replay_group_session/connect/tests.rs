use super::*;
use crate::io::replay_group_session::{
    GroupSessionCaptureLimits, GroupSessionCompletionError, GroupSessionRunError,
    RecordedGroupSession,
};
use crate::time::VirtualClock;
use crate::util::DetEntropy;
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::EntropyCaptureLimits;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Wake;

#[derive(Default)]
struct Fixture {
    input: &'static [u8],
    output: Vec<u8>,
    flushes: usize,
    shutdowns: usize,
}
impl Fixture {
    fn new(input: &'static [u8]) -> Self { Self { input, ..Self::default() } }
}
impl AsyncRead for Fixture {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = buf.remaining().min(this.input.len());
        buf.put_slice(&this.input[..n]);
        this.input = &this.input[n..];
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Fixture {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let start = this.output.len();
        for buf in bufs { this.output.extend_from_slice(buf); }
        Poll::Ready(Ok(this.output.len() - start))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flushes += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}
fn limits() -> GroupSessionCaptureLimits {
    GroupSessionCaptureLimits {
        max_streams: 12, max_effects: 96,
        per_stream: IoCaptureLimits::new(32, 4096, 4096, 8),
        entropy: EntropyCaptureLimits::new(32, 256, 4), clock_observations: 16,
    }
}
fn session_with(limits: GroupSessionCaptureLimits) -> RecordingGroupSession<VirtualClock> {
    RecordingGroupSession::new(Arc::new(DetEntropy::new(7)), Arc::new(VirtualClock::new()), limits).unwrap()
}
fn capture_session() -> RecordingGroupSession<VirtualClock> { session_with(limits()) }
fn attempt(n: u64) -> ConnectionAttempt { ConnectionAttempt::new(n * 2, n * 2 + 1).unwrap() }
fn resolved<T>(value: Poll<T>) -> T {
    match value { Poll::Ready(value) => value, Poll::Pending => panic!("expected a completed operation") }
}
fn poll<F: Future>(future: &mut Pin<Box<F>>, waker: &Waker) -> Poll<F::Output> {
    future.as_mut().poll(&mut Context::from_waker(waker))
}
fn immediate<F: Future>(future: F) -> F::Output { resolved(poll(&mut Box::pin(future), Waker::noop())) }
fn read(io: &mut (impl AsyncRead + Unpin), size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; size];
    let mut buf = ReadBuf::new(&mut bytes);
    resolved(Pin::new(io).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf))?;
    Ok(buf.filled().to_vec())
}
fn write(io: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> io::Result<usize> {
    resolved(Pin::new(io).poll_write(&mut Context::from_waker(Waker::noop()), bytes))
}
fn captured() -> RecordedGroupSession {
    let session = capture_session();
    let mut io = immediate(session.connect_with(attempt(0), b"endpoint", 64, || async { Ok(Fixture::new(b"yes")) })).unwrap();
    assert_eq!(write(&mut io, b"hello").unwrap(), 5);
    assert_eq!(read(&mut io, 3).unwrap(), b"yes");
    assert_eq!(io.into_inner().output, b"hello");
    session.finish().unwrap()
}

#[test]
fn successful_connection_owns_real_stream_and_replays_without_a_factory() {
    let session = capture_session();
    let calls = AtomicUsize::new(0);
    let future = session.connect_with(attempt(0), b"endpoint", 64, || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(Fixture::new(b"yes")) }
    });
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut io = immediate(future).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(write(&mut io, b"hello").unwrap(), 5);
    assert_eq!(read(&mut io, 3).unwrap(), b"yes");
    assert_eq!(io.into_inner().output, b"hello", "journal bytes never reach the real provider");
    let tape = session.finish().unwrap();
    assert_eq!(tape.stream_ids().collect::<Vec<_>>(), [0, 1]);
    assert_eq!(tape.effects(), 4);
    let replay = tape.replay();
    let mut io = immediate(replay.connect(attempt(0), b"endpoint")).unwrap();
    assert_eq!(write(&mut io, b"hello").unwrap(), 5);
    assert_eq!(read(&mut io, 3).unwrap(), b"yes");
    drop(io);
    replay.verify_complete().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn original_custom_error_is_not_replaced_by_capture_and_replay_retains_its_kind() {
    let session = capture_session();
    let original = immediate(session.connect_with(attempt(0), b"private-endpoint", 64, || async {
        Err::<Fixture, _>(io::Error::other("original-private-diagnostic"))
    })).unwrap_err();
    assert_eq!(original.to_string(), "original-private-diagnostic");
    let tape = session.finish().unwrap();
    assert_eq!(tape.stream_ids().collect::<Vec<_>>(), [0]);
    let replay = tape.replay();
    let error = immediate(replay.connect(attempt(0), b"private-endpoint")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(!error.to_string().contains("original-private-diagnostic"));
    replay.verify_complete().unwrap();
}

#[test]
fn native_error_codes_survive_failed_connection_replay() {
    let session = capture_session();
    let original = immediate(session.connect_with(attempt(0), b"address", 64, || async {
        Err::<Fixture, _>(io::Error::from_raw_os_error(111))
    })).unwrap_err();
    let replay = session.finish().unwrap().replay();
    let replayed = immediate(replay.connect(attempt(0), b"address")).unwrap_err();
    assert_eq!(replayed.raw_os_error(), original.raw_os_error());
    assert_eq!(replayed.kind(), original.kind());
    replay.verify_complete().unwrap();
}

#[test]
fn failed_attempt_then_clock_entropy_and_retry_keep_one_cross_provider_order() {
    let session = capture_session();
    assert_eq!(immediate(session.connect_with(attempt(0), b"first", 64, || async {
        Err::<Fixture, _>(io::ErrorKind::PermissionDenied.into())
    })).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    let time = session.clock().now();
    let nonce = session.entropy().next_u64().to_le_bytes();
    let mut io = immediate(session.connect_with(attempt(1), &nonce, 64, || async { Ok(Fixture::new(b"r")) })).unwrap();
    assert_eq!(read(&mut io, 1).unwrap(), b"r");
    io.into_inner();
    let replay = session.finish().unwrap().replay();
    assert_eq!(immediate(replay.connect(attempt(0), b"first")).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(replay.clock().try_now().unwrap(), time);
    let replay_nonce = replay.entropy().try_next_u64().unwrap().to_le_bytes();
    assert_eq!(replay_nonce, nonce);
    let mut io = immediate(replay.connect(attempt(1), &replay_nonce)).unwrap();
    assert_eq!(read(&mut io, 1).unwrap(), b"r");
    drop(io);
    replay.verify_complete().unwrap();
}

#[test]
fn changed_request_or_bound_data_identity_is_sticky_even_when_error_is_ignored() {
    for changed_target in [false, true] {
        let replay = captured().replay();
        let (id, key): (_, &[u8]) = if changed_target {
            (ConnectionAttempt::new(0, 9).unwrap(), b"endpoint")
        } else { (attempt(0), b"ENDPOINT") };
        assert!(immediate(replay.connect(id, key)).is_err());
        assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    }
}

#[test]
fn unknown_extra_connection_invalidates_an_otherwise_complete_empty_window() {
    let replay = capture_session().finish().unwrap().replay();
    replay.verify_complete().unwrap();
    assert!(immediate(replay.connect(attempt(3), b"never-captured")).is_err());
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
}

#[test]
fn reused_attempt_never_reopens_a_completed_journal() {
    let session = capture_session();
    immediate(session.connect_with(attempt(0), b"x", 64, || async { Ok(Fixture::default()) })).unwrap().into_inner();
    let replay = session.finish().unwrap().replay();
    drop(immediate(replay.connect(attempt(0), b"x")).unwrap());
    replay.verify_complete().unwrap();
    assert!(immediate(replay.connect(attempt(0), b"x")).is_err());
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
}

#[test]
fn request_and_stream_bounds_refuse_capture_without_losing_live_success() {
    for mode in 0..3 {
        let mut limits = limits();
        if mode != 0 { limits.max_streams = mode - 1; }
        let session = session_with(limits);
        let max_key = if mode == 0 { 1 } else { 64 };
        let calls = AtomicUsize::new(0);
        let mut io = immediate(session.connect_with(attempt(0), b"long-key", max_key, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(Fixture::new(b"real")) }
        })).unwrap();
        assert_eq!(read(&mut io, 4).unwrap(), b"real");
        assert_eq!(write(&mut io, b"sent").unwrap(), 4);
        assert_eq!(io.into_inner().output, b"sent");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Limit(_))));
    }
}

#[test]
fn journal_has_its_own_limits_without_widening_data_limits() {
    let mut bounds = limits();
    bounds.per_stream = IoCaptureLimits::new(1, 1, 0, 0);
    let session = session_with(bounds);
    let mut io = immediate(session.connect_with(attempt(0), b"key", 64, || async { Ok(Fixture::new(b"x")) })).unwrap();
    assert_eq!(read(&mut io, 1).unwrap(), b"x");
    io.into_inner();
    let replay = session.finish().unwrap().replay();
    let mut io = immediate(replay.connect(attempt(0), b"key")).unwrap();
    assert_eq!(read(&mut io, 1).unwrap(), b"x");
    drop(io);
    replay.verify_complete().unwrap();
}

#[test]
fn duplicate_data_identity_preserves_both_original_providers_and_refuses_capture() {
    let session = capture_session();
    let original = session.register(1, Fixture::new(b"old")).unwrap();
    let mut io = immediate(session.connect_with(attempt(0), b"key", 64, || async { Ok(Fixture::new(b"new")) })).unwrap();
    assert_eq!(read(&mut io, 3).unwrap(), b"new");
    assert_eq!(original.into_inner().input, b"old");
    io.into_inner();
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::DuplicateStream(1))));
}

struct PendingDial { ready: Arc<AtomicBool>, drops: Arc<AtomicUsize>, bytes: &'static [u8] }
impl Future for PendingDial {
    type Output = io::Result<Fixture>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.ready.load(Ordering::SeqCst) { Poll::Ready(Ok(Fixture::new(self.bytes))) }
        else { Poll::Pending }
    }
}
impl Drop for PendingDial {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
}
#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn counting() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    (counter, waker)
}

#[test]
fn concurrent_attempts_replay_reverse_completion_with_clock_prerequisite_and_wakeups() {
    let session = capture_session();
    let a_ready = Arc::new(AtomicBool::new(false));
    let b_ready = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut a = Box::pin(session.connect_with(attempt(0), b"a", 64, || PendingDial {
        ready: Arc::clone(&a_ready), drops: Arc::clone(&drops), bytes: b"A",
    }));
    let mut b = Box::pin(session.connect_with(attempt(1), b"b", 64, || PendingDial {
        ready: Arc::clone(&b_ready), drops: Arc::clone(&drops), bytes: b"B",
    }));
    assert!(poll(&mut a, Waker::noop()).is_pending());
    assert!(poll(&mut b, Waker::noop()).is_pending());
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::LiveStreams(2))));
    let time = session.clock().now();
    b_ready.store(true, Ordering::SeqCst);
    let mut stream_b = resolved(poll(&mut b, Waker::noop())).unwrap();
    assert_eq!(read(&mut stream_b, 1).unwrap(), b"B");
    stream_b.into_inner();
    a_ready.store(true, Ordering::SeqCst);
    let mut stream_a = resolved(poll(&mut a, Waker::noop())).unwrap();
    assert_eq!(read(&mut stream_a, 1).unwrap(), b"A");
    stream_a.into_inner();
    drop(a); drop(b);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    let replay = session.finish().unwrap().replay();
    let mut a = Box::pin(replay.connect(attempt(0), b"a"));
    let mut b = Box::pin(replay.connect(attempt(1), b"b"));
    let (a_count, a_waker) = counting();
    let (b_count, b_waker) = counting();
    assert!(poll(&mut b, &b_waker).is_pending());
    assert_eq!(b_count.0.load(Ordering::SeqCst), 0);
    assert!(poll(&mut a, &a_waker).is_pending());
    assert_eq!(b_count.0.load(Ordering::SeqCst), 1);
    assert!(poll(&mut b, &b_waker).is_pending());
    assert_eq!(replay.clock().try_now().unwrap(), time);
    assert_eq!(b_count.0.load(Ordering::SeqCst), 2);
    assert!(poll(&mut a, &a_waker).is_pending());
    let mut stream_b = resolved(poll(&mut b, &b_waker)).unwrap();
    assert_eq!(read(&mut stream_b, 1).unwrap(), b"B");
    assert!(a_count.0.load(Ordering::SeqCst) > 0);
    let mut stream_a = resolved(poll(&mut a, &a_waker)).unwrap();
    assert_eq!(read(&mut stream_a, 1).unwrap(), b"A");
    drop(stream_a); drop(stream_b); drop(a); drop(b);
    replay.verify_complete().unwrap();
}

#[test]
fn cancelled_attempt_drops_its_real_future_once_and_cannot_publish_a_partial_capture() {
    let session = capture_session();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut future = Box::pin(session.connect_with(attempt(0), b"wait", 64, || PendingDial {
        ready: Arc::new(AtomicBool::new(false)), drops: Arc::clone(&drops), bytes: b"never",
    }));
    assert!(poll(&mut future, Waker::noop()).is_pending());
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::AbandonedStream(0))));
}

#[test]
fn unpolled_attempt_has_no_source_or_timeline_effect() {
    let session = capture_session();
    let calls = AtomicUsize::new(0);
    let future = session.connect_with(attempt(0), b"unused", 64, || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(Fixture::default()) }
    });
    drop(future);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.finish().unwrap().effects(), 0);
}

#[test]
fn source_factory_and_poll_cannot_hide_same_session_effects() {
    for in_factory in [false, true] {
        let session = capture_session();
        let clock = session.clock();
        let stream = immediate(session.connect_with(attempt(0), b"opaque", 64, || {
            if in_factory { clock.now(); }
            async move {
                if !in_factory { clock.now(); }
                Ok(Fixture::new(b"still-live"))
            }
        })).unwrap();
        assert_eq!(stream.into_inner().input, b"still-live");
        assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Overlap)));
    }
}

struct DropDial {
    clock: Option<Arc<super::super::GroupRecordingClock<VirtualClock>>>,
    panic: bool,
}
impl Future for DropDial {
    type Output = io::Result<Fixture>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(Fixture::default()))
    }
}
impl Drop for DropDial {
    fn drop(&mut self) {
        if let Some(clock) = &self.clock { clock.now(); }
        assert!(!self.panic, "connector destructor panic sentinel");
    }
}

#[test]
fn source_destruction_is_inside_the_opaque_boundary_before_completion() {
    let session = capture_session();
    let io = immediate(session.connect_with(attempt(0), b"drop", 64, || DropDial {
        clock: Some(session.clock()), panic: false,
    })).unwrap();
    io.into_inner();
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Overlap)));
}

#[test]
fn connector_construction_poll_and_destruction_panics_never_finish_capture() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let session = capture_session();
    assert!(catch_unwind(AssertUnwindSafe(|| immediate(session.connect_with(
        attempt(0), b"construct", 64, || -> std::future::Ready<io::Result<Fixture>> {
            panic!("connector factory panic sentinel")
        },
    )))).is_err());
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Interrupted)));

    let session = capture_session();
    assert!(catch_unwind(AssertUnwindSafe(|| immediate(session.connect_with(attempt(0), b"poll", 64, || async {
        panic!("connector poll panic sentinel");
        #[allow(unreachable_code)]
        Ok::<_, io::Error>(Fixture::default())
    })))).is_err());
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Interrupted)));

    let session = capture_session();
    assert!(catch_unwind(AssertUnwindSafe(|| immediate(session.connect_with(attempt(0), b"drop", 64, || DropDial {
        clock: None, panic: true,
    })))).is_err());
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Interrupted)));
}

fn journal_only(marker: &'static [u8], data: bool) -> RecordedGroupSession {
    let session = capture_session();
    let id = attempt(0);
    let mut journal = session.register(id.journal_stream(), Fixture::new(marker)).unwrap();
    let target = id.data_stream().to_le_bytes();
    let bufs = [IoSlice::new(REQUEST_DOMAIN), IoSlice::new(&target), IoSlice::new(b"key")];
    resolved(Pin::new(&mut journal).poll_write_vectored(&mut Context::from_waker(Waker::noop()), &bufs)).unwrap();
    read(&mut journal, 1).unwrap();
    journal.into_inner();
    if data { session.register(id.data_stream(), Fixture::default()).unwrap().into_inner(); }
    session.finish().unwrap()
}

#[test]
fn malformed_success_or_missing_data_stream_is_sticky_not_a_fake_connection() {
    for (marker, data) in [(&[2][..], true), (&[1][..], false), (&[][..], true)] {
        let replay = journal_only(marker, data).replay();
        assert!(immediate(replay.connect(attempt(0), b"key")).is_err());
        assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    }
}

#[test]
fn cancelled_replay_attempt_invalidates_its_peer_and_output_gate() {
    let session = capture_session();
    let clock = session.clock();
    clock.now();
    immediate(session.connect_with(attempt(0), b"after-clock", 64, || async { Ok(Fixture::default()) })).unwrap().into_inner();
    let replay = session.finish().unwrap().replay();
    let mut future = Box::pin(replay.connect(attempt(0), b"after-clock"));
    assert!(poll(&mut future, Waker::noop()).is_pending());
    drop(future);
    assert!(replay.clock().try_now().is_err());
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    let result = immediate(replay.run(1, |_| Box::pin(async { "not accepted" })));
    assert!(matches!(result, Err(GroupSessionRunError::Replay(_))));
}

#[test]
fn successful_connection_preserves_vectored_flush_shutdown_and_eof() {
    let session = capture_session();
    let mut io = immediate(session.connect_with(attempt(0), b"full-io", 64, || async { Ok(Fixture::default()) })).unwrap();
    let bufs = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(io.is_write_vectored());
    assert_eq!(resolved(Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs)).unwrap(), 3);
    resolved(Pin::new(&mut io).poll_flush(&mut cx)).unwrap();
    resolved(Pin::new(&mut io).poll_shutdown(&mut cx)).unwrap();
    assert_eq!(read(&mut io, 1).unwrap(), b"");
    let original = io.into_inner();
    assert_eq!(original.output, b"abc");
    assert_eq!((original.flushes, original.shutdowns), (1, 1));
    let replay = session.finish().unwrap().replay();
    let mut io = immediate(replay.connect(attempt(0), b"full-io")).unwrap();
    assert!(io.is_write_vectored());
    assert_eq!(resolved(Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs)).unwrap(), 3);
    resolved(Pin::new(&mut io).poll_flush(&mut cx)).unwrap();
    resolved(Pin::new(&mut io).poll_shutdown(&mut cx)).unwrap();
    assert_eq!(read(&mut io, 1).unwrap(), b"");
    drop(io);
    replay.verify_complete().unwrap();
}

#[test]
fn identity_validation_and_debug_do_not_expose_request_or_provider_data() {
    assert_eq!(ConnectionAttempt::new(3, 3), Err(ConnectionIdentityError));
    fn bounds<T: Send + Sync + Unpin>() {}
    bounds::<RecordingConnection<Fixture>>();
    let session = capture_session();
    let io = immediate(session.connect_with(attempt(0), b"private-target", 64, || async { Ok(Fixture::new(b"private-data")) })).unwrap();
    let debug = format!("{io:?}");
    assert!(!debug.contains("private-target"));
    assert!(!debug.contains("private-data"));
    io.into_inner();
    session.finish().unwrap();
}
