use super::*;
use crate::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::io::replay::IoCaptureLimits;
use crate::io::replay_session::SessionCaptureLimits;
use crate::time::{TimeSource, VirtualClock};
use crate::types::Time;
use crate::util::{DetEntropy, EntropySource};
use crate::util::entropy_replay::EntropyCaptureLimits;
use std::io::{self, IoSlice};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

struct Notice(AtomicBool);
impl Wake for Notice {
    fn wake(self: Arc<Self>) { self.0.store(true, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.store(true, Ordering::SeqCst); }
}

// Unlike an unconditional polling loop, this driver refuses a missing wakeup.
pub(super) fn drive<F: Future>(future: F) -> Result<F::Output, &'static str> {
    let notice = Arc::new(Notice(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&notice));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    for _ in 0..1000 {
        notice.0.store(false, Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return Ok(output),
            Poll::Pending if notice.0.load(Ordering::SeqCst) => {}
            Poll::Pending => return Err("no wakeup"),
        }
    }
    Err("poll bound")
}

#[derive(Debug)]
struct Choppy {
    ready: [bool; 5],
    offset: usize,
    written: Vec<u8>,
    calls: Arc<AtomicUsize>,
    fail: bool,
    panic_read: bool,
}
impl Choppy {
    fn new() -> Self {
        Self { ready: [false; 5], offset: 0, written: Vec::new(), calls: Arc::new(AtomicUsize::new(0)), fail: false, panic_read: false }
    }
    fn pending(&mut self, kind: usize, cx: &mut Context<'_>) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ready = self.ready[kind];
        self.ready[kind] = !ready;
        if !ready { cx.waker().wake_by_ref(); }
        !ready
    }
}
impl AsyncRead for Choppy {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.panic_read { panic!("provider sentinel"); }
        if this.pending(0, cx) { return Poll::Pending; }
        if this.fail { return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())); }
        let n = (3 - this.offset).min(buf.remaining()).min(1);
        buf.put_slice(&b"yes"[this.offset..this.offset + n]);
        this.offset += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Choppy {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending(1, cx) { return Poll::Pending; }
        let n = bytes.len().min(2);
        this.written.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending(2, cx) { return Poll::Pending; }
        for buf in bufs { this.written.extend_from_slice(buf); }
        Poll::Ready(Ok(bufs.iter().map(|b| b.len()).sum()))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.get_mut().pending(3, cx) { Poll::Pending } else { Poll::Ready(Ok(())) }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.get_mut().pending(4, cx) { Poll::Pending } else { Poll::Ready(Ok(())) }
    }
}
fn bounds() -> PollCaptureLimits {
    PollCaptureLimits { max_polls: 128, max_io_polls: 256, max_write_bytes: 4096, max_vectored_slices: 8 }
}
fn session(io: Choppy) -> OrderedRecordingSession<Choppy, VirtualClock> {
    OrderedRecordingSession::new(io, Arc::new(DetEntropy::new(42)), Arc::new(VirtualClock::new()),
        SessionCaptureLimits {
            io: IoCaptureLimits::new(128, 1024, 4096, 8),
            entropy: EntropyCaptureLimits::new(256, 4096, 8), clock_observations: 256,
        }, 1024).unwrap()
}

pub(super) async fn receive<I, E, C>(io: &mut I, entropy: &E, clock: &C) -> Result<(Vec<u8>, Vec<(Time, u64)>), io::ErrorKind>
where I: AsyncRead + Unpin, E: EntropySource + ?Sized, C: TimeSource + ?Sized {
    let mut out = Vec::new();
    let mut observations = Vec::new();
    loop {
        let mut byte = [0];
        let n = poll_fn(|cx| {
            observations.push((clock.now(), entropy.next_u64()));
            let mut rb = ReadBuf::new(&mut byte);
            Pin::new(&mut *io).poll_read(cx, &mut rb)
                .map(|r| r.map(|()| rb.filled().len()).map_err(|e| e.kind()))
        }).await?;
        if n == 0 { return Ok((out, observations)); }
        out.extend_from_slice(&byte[..n]);
    }
}
pub(super) fn capture() -> PolledRecordedSession {
    let (original, _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| {
        Box::pin(receive(p.io, p.entropy, p.clock))
    })).unwrap();
    assert_eq!(original.unwrap().0, b"yes");
    tape.unwrap()
}

#[test]
fn actual_pending_replay_progresses_without_the_original_source_wakeup() {
    let source = Choppy::new();
    let calls = Arc::clone(&source.calls);
    let (original, source, tape) = drive(session(source).record_polls(bounds(), |p| {
        Box::pin(receive(p.io, p.entropy, p.clock))
    })).unwrap();
    let before = calls.load(Ordering::SeqCst);
    let tape = tape.unwrap();
    assert_eq!(tape.consumer_polls(), 5); // four Pending reads, one final Ready poll
    assert_eq!(tape.io_polls(), 8);
    drop(source);
    let replay = drive(tape.run(128, |p| Box::pin(receive(p.io, p.entropy, p.clock))))
        .unwrap().unwrap();
    assert_eq!(replay, original);
    assert_eq!(calls.load(Ordering::SeqCst), before);
}

#[test]
fn negative_control_completed_effect_order_alone_loses_the_pending_wakeup() {
    let tape = capture();
    // Deliberately drop only the new poll transcript to exercise the old public
    // completed-effect runner. It parks on the first read before the next clock.
    assert!(matches!(drive(tape.ordered.replay().run(128, |p| {
        Box::pin(receive(p.io, p.entropy, p.clock))
    })), Err("no wakeup")));
}

#[test]
fn capture_and_replay_futures_are_send_for_native_owned_tasks() {
    fn assert_send<T: Send>(_: &T) {}
    let record = session(Choppy::new()).record_polls_send(bounds(), |p| Box::pin(receive(p.io, p.entropy, p.clock)));
    assert_send(&record);
    let (original, _, tape) = drive(record).unwrap();
    let replay = tape.unwrap().run_send(128, |p| Box::pin(receive(p.io, p.entropy, p.clock)));
    assert_send(&replay);
    assert_eq!(drive(replay).unwrap().unwrap(), original);
}

#[test]
fn recorded_errors_remain_application_outputs() {
    let mut io = Choppy::new(); io.fail = true;
    let (original, _, tape) = drive(session(io).record_polls(bounds(), |p| Box::pin(receive(p.io, p.entropy, p.clock)))).unwrap();
    assert_eq!(original, Err(io::ErrorKind::ConnectionReset));
    assert_eq!(drive(tape.unwrap().run(128, |p| Box::pin(receive(p.io, p.entropy, p.clock)))).unwrap().unwrap(), original);
}

#[test]
fn pending_request_mismatch_poison_is_shared_with_entropy() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| Box::pin(async move {
        p.io.write_all(b"secret").await.unwrap();
    }))).unwrap();
    let replay = drive(tape.unwrap().run(128, |p| Box::pin(async move {
        let error = p.io.write_all(b"change").await.unwrap_err();
        assert!(error.get_ref().unwrap().is::<PollReplayError>());
        assert!(p.entropy.try_next_u64().is_err());
    }))).unwrap();
    assert!(matches!(replay, Err(PolledRunError::Poll(PollReplayError { reason: PollMismatch::Request, .. }))));
}

#[test]
fn pending_read_capacity_is_checked_before_modifying_the_destination() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| Box::pin(async move {
        let mut bytes = [0]; p.io.read(&mut bytes).await.unwrap();
    }))).unwrap();
    let replay = drive(tape.unwrap().run(128, |p| Box::pin(async move {
        let mut bytes = [0xa5; 2];
        assert!(p.io.read(&mut bytes).await.is_err());
        assert_eq!(bytes, [0xa5; 2]);
    }))).unwrap();
    assert!(matches!(replay, Err(PolledRunError::Poll(_))));
}

async fn vector<I: AsyncWrite + Unpin>(io: &mut I, changed: bool) {
    let bufs = if changed { [IoSlice::new(b"ab"), IoSlice::new(b"c")] }
        else { [IoSlice::new(b"a"), IoSlice::new(b"bc")] };
    let _ = poll_fn(|cx| Pin::new(&mut *io).poll_write_vectored(cx, &bufs)).await;
}
#[test]
fn vectored_boundaries_are_checked_even_on_a_pending_poll() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| Box::pin(vector(p.io, false)))).unwrap();
    assert!(matches!(drive(tape.unwrap().run(128, |p| Box::pin(vector(p.io, true)))).unwrap(), Err(PolledRunError::Poll(_))));
}

#[test]
fn pending_write_flush_and_shutdown_are_all_reproduced() {
    async fn send<I: AsyncWrite + Unpin>(io: &mut I) -> io::Result<()> {
        io.write_all(b"abcde").await?;
        io.flush().await?;
        io.shutdown().await
    }
    let (out, source, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| Box::pin(send(p.io)))).unwrap();
    out.unwrap(); assert_eq!(source.written, b"abcde");
    let tape = tape.unwrap(); assert_eq!(tape.io_polls(), 10);
    drive(tape.run(128, |p| Box::pin(send(p.io)))).unwrap().unwrap().unwrap();
}

#[test]
fn capture_limits_do_not_change_live_outcome_or_discard_stream_owner() {
    for kind in 0..4 {
        let mut limit = bounds();
        match kind { 0 => limit.max_polls = 0, 1 => limit.max_io_polls = 0, 2 => limit.max_write_bytes = 0, _ => limit.max_vectored_slices = 0 }
        let ((), source, tape) = drive(session(Choppy::new()).record_polls(limit, |p| Box::pin(async move {
            p.io.write_all(b"abc").await.unwrap();
            vector(p.io, false).await;
        }))).unwrap();
        assert_eq!(source.written, b"abcabc");
        assert!(tape.unwrap_err().polls.is_some());
    }
}

#[test]
fn replay_poll_ceiling_refuses_before_invoking_factory() {
    let tape = capture();
    let invoked = AtomicBool::new(false);
    let result = drive(tape.run(0, |_| {
        invoked.store(true, Ordering::SeqCst);
        Box::pin(async {})
    })).unwrap();
    assert!(matches!(result, Err(PolledRunError::Budget { limit: 0, .. })));
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn changed_consumer_boundary_is_terminal_not_an_unbounded_self_wake_loop() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |_| Box::pin(async {}))).unwrap();
    let result = drive(tape.unwrap().run(1, |_| Box::pin(std::future::pending::<()>()))).unwrap();
    assert!(matches!(result, Err(PolledRunError::Poll(PollReplayError { reason: PollMismatch::Boundary, .. }))));
}

struct FinalClock<'a, C: TimeSource + ?Sized>(&'a C);
impl<C: TimeSource + ?Sized> Future for FinalClock<'_, C> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { Poll::Ready(()) }
}
impl<C: TimeSource + ?Sized> Drop for FinalClock<'_, C> {
    fn drop(&mut self) { self.0.now(); }
}
#[test]
fn factory_and_destructor_effects_have_distinct_checked_checkpoints() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| {
        p.entropy.next_u64();
        Box::pin(FinalClock(p.clock))
    })).unwrap();
    drive(tape.unwrap().run(1, |p| {
        p.entropy.next_u64();
        Box::pin(FinalClock(p.clock))
    })).unwrap().unwrap();
}

#[test]
fn missing_destructor_effect_refuses_an_otherwise_complete_result() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| Box::pin(FinalClock(p.clock)))).unwrap();
    assert!(matches!(drive(tape.unwrap().run(1, |_| Box::pin(async {}))).unwrap(), Err(PolledRunError::Poll(PollReplayError { reason: PollMismatch::Completion, .. }))));
}

#[test]
fn missing_factory_effect_is_refused_before_first_consumer_poll() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |p| {
        p.clock.now(); Box::pin(async {})
    })).unwrap();
    assert!(matches!(drive(tape.unwrap().run(1, |_| Box::pin(async {}))).unwrap(), Err(PolledRunError::Poll(PollReplayError { reason: PollMismatch::Construction, .. }))));
}

#[test]
fn swallowed_provider_panic_invalidates_capture() {
    let mut source = Choppy::new(); source.panic_read = true;
    let ((), _, tape) = drive(session(source).record_polls(bounds(), |p| Box::pin(async move {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = [0]; let mut rb = ReadBuf::new(&mut b);
            let _ = Pin::new(&mut *p.io).poll_read(&mut Context::from_waker(Waker::noop()), &mut rb);
        }));
    }))).unwrap();
    assert_eq!(tape.unwrap_err().polls, Some(PollCaptureError::Interrupted));
}

#[test]
fn already_used_ordered_session_cannot_publish_a_partial_poll_window() {
    let source = session(Choppy::new()); source.clock().now();
    let (value, _, tape) = drive(source.record_polls(bounds(), |_| Box::pin(async { 7 }))).unwrap();
    assert_eq!(value, 7);
    assert_eq!(tape.unwrap_err().polls, Some(PollCaptureError::Inconsistent));
}

#[test]
fn extra_pending_io_after_tape_end_is_not_manufactured_eof() {
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), |_| Box::pin(async {}))).unwrap();
    let result = drive(tape.unwrap().run(1, |p| Box::pin(async move {
        let mut b = [0]; assert!(p.io.read(&mut b).await.is_err());
    }))).unwrap();
    assert!(matches!(result, Err(PolledRunError::Poll(PollReplayError { reason: PollMismatch::Exhausted, .. }))));
}

#[test]
fn pending_digest_and_payload_are_not_in_debug_output() {
    let tape = capture();
    let debug = format!("{tape:?}");
    assert!(!debug.contains("yes"));
    assert!(!debug.contains("digest"));
    assert!(!debug.contains("Choppy"));
}

pub(super) fn empty() -> PolledRecordedSession {
    drive(session(Choppy::new()).record_polls(bounds(), |_| Box::pin(async {}))).unwrap().2.unwrap()
}

struct YieldOnce { yielded: bool, dropped: Arc<AtomicUsize> }
impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded { Poll::Ready(()) }
        else { self.yielded = true; cx.waker().wake_by_ref(); Poll::Pending }
    }
}
impl Drop for YieldOnce {
    fn drop(&mut self) { self.dropped.fetch_add(1, Ordering::SeqCst); }
}
#[test]
fn dropping_a_suspended_replay_destroys_its_consumer_once_without_a_result() {
    let recorded_drop = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&recorded_drop);
    let ((), _, tape) = drive(session(Choppy::new()).record_polls(bounds(), move |_| {
        Box::pin(YieldOnce { yielded: false, dropped: seen })
    })).unwrap();
    assert_eq!(recorded_drop.load(Ordering::SeqCst), 1);
    let replay_drop = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&replay_drop);
    let mut driver = Box::pin(tape.unwrap().run(128, move |_| Box::pin(YieldOnce { yielded: false, dropped: seen })));
    assert!(driver.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(driver);
    assert_eq!(replay_drop.load(Ordering::SeqCst), 1);
}

#[test]
fn nested_pending_io_mode_cannot_pass_completed_effect_coverage() {
    let mut tape = capture();
    tape.ordered.order.poll_aware = true;
    assert!(!tape.polls.covers(&tape.ordered));
}
