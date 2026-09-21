use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

fn limits() -> IoGroupCaptureLimits {
    IoGroupCaptureLimits { max_streams: 4, max_events: 128, per_stream: IoCaptureLimits::new(64, 4096, 4096, 16) }
}

#[derive(Default)]
struct Fixture {
    input: &'static [u8], output: Vec<u8>, pending: bool, error: bool, panic: bool,
    vector_calls: usize, polls: Arc<AtomicUsize>,
}
impl Fixture {
    fn new(input: &'static [u8]) -> Self { Self { input, ..Self::default() } }
}
impl AsyncRead for Fixture {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        if std::mem::take(&mut this.panic) { panic!("provider panic sentinel"); }
        if std::mem::take(&mut this.pending) { return Poll::Pending; }
        if this.error { return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())); }
        let n = buf.remaining().min(this.input.len());
        buf.put_slice(&this.input[..n]);
        this.input = &this.input[n..];
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Fixture {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        this.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.vector_calls += 1;
        let before = this.output.len();
        for buf in bufs { this.output.extend_from_slice(buf); }
        Poll::Ready(Ok(this.output.len() - before))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

fn read(io: &mut (impl AsyncRead + Unpin), size: usize, waker: &Waker) -> Poll<io::Result<Vec<u8>>> {
    let mut out = vec![0; size];
    let mut buf = ReadBuf::new(&mut out);
    let result = Pin::new(io).poll_read(&mut Context::from_waker(waker), &mut buf);
    result.map(|result| result.map(|()| buf.filled().to_vec()))
}
fn write(io: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Poll<io::Result<usize>> {
    Pin::new(io).poll_write(&mut Context::from_waker(Waker::noop()), bytes)
}
fn ready_value<T>(value: Poll<io::Result<T>>) -> T {
    match value { Poll::Ready(Ok(value)) => value, _ => panic!("expected successful completed I/O") }
}
fn two_reads() -> RecordedIoGroup {
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(41, Fixture::new(b"a")).unwrap();
    let mut b = group.register(73, Fixture::new(b"b")).unwrap();
    assert_eq!(ready_value(read(&mut a, 1, Waker::noop())), b"a");
    assert_eq!(ready_value(read(&mut b, 1, Waker::noop())), b"b");
    a.into_inner(); b.into_inner();
    group.finish().unwrap()
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
fn reordered_cross_stream_poll_waits_and_is_woken_by_its_prerequisite() {
    let replay = two_reads().replay();
    // Opening order need not match registration order.
    let mut b = replay.open(73).unwrap();
    let mut a = replay.open(41).unwrap();
    let (counter, waker) = counting();
    assert!(read(&mut b, 1, &waker).is_pending());
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Remaining(2)));
    assert_eq!(ready_value(read(&mut a, 1, Waker::noop())), b"a");
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert_eq!(ready_value(read(&mut b, 1, &waker)), b"b");
    drop(a); drop(b);
    replay.verify_complete().unwrap();
}

#[test]
fn changing_a_write_invalidates_other_streams_even_when_error_is_ignored() {
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(1, Fixture::default()).unwrap();
    let mut b = group.register(2, Fixture::new(b"x")).unwrap();
    ready_value(write(&mut a, b"secret request"));
    ready_value(read(&mut b, 1, Waker::noop()));
    a.into_inner(); b.into_inner();
    let replay = group.finish().unwrap().replay();
    let mut a = replay.open(1).unwrap();
    let mut b = replay.open(2).unwrap();
    let (counter, waker) = counting();
    assert!(read(&mut b, 1, &waker).is_pending());
    assert!(matches!(write(&mut a, b"wrong! request"), Poll::Ready(Err(_))));
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(matches!(read(&mut b, 1, &waker), Poll::Ready(Err(_))));
    assert!(matches!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(IoGroupReplayError::Stream { stream: 1, .. }))));
}

#[test]
fn wrong_operation_on_eligible_stream_is_not_an_infinite_opposite_half_wait() {
    let replay = two_reads().replay();
    let mut a = replay.open(41).unwrap();
    assert!(matches!(write(&mut a, b""), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::Operation { stream: 41, expected: IoOperation::Read, actual: IoOperation::Write }
    )));
}

#[test]
fn original_io_error_is_replayed_without_becoming_a_group_divergence() {
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(1, Fixture { error: true, ..Fixture::default() }).unwrap();
    assert!(matches!(read(&mut a, 7, Waker::noop()), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset));
    a.into_inner();
    let replay = group.finish().unwrap().replay();
    let mut a = replay.open(1).unwrap();
    assert!(matches!(read(&mut a, 7, Waker::noop()), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset));
    replay.verify_complete().unwrap();
}

#[test]
fn limits_refuse_capture_without_replacing_live_results_or_losing_providers() {
    for local in [false, true] {
        let mut bound = limits();
        if local { bound.per_stream.max_operations = 0; } else { bound.max_events = 0; }
        let group = IoRecordingGroup::new(bound);
        let mut a = group.register(1, Fixture::default()).unwrap();
        assert_eq!(ready_value(write(&mut a, b"real data")), 9);
        assert_eq!(a.into_inner().output, b"real data");
        assert!(group.finish().is_err());
    }
}

#[test]
fn pending_polls_do_not_invent_completions_and_finish_can_be_retried() {
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(9, Fixture { input: b"x", pending: true, ..Fixture::default() }).unwrap();
    assert!(matches!(group.finish(), Err(IoGroupCaptureError::LiveStreams(1))));
    assert!(read(&mut a, 1, Waker::noop()).is_pending());
    assert_eq!(ready_value(read(&mut a, 1, Waker::noop())), b"x");
    a.into_inner();
    let tape = group.finish().unwrap();
    assert_eq!(tape.operations(), 1);
    assert!(matches!(group.finish(), Err(IoGroupCaptureError::Finished)));
    let error = group.register(10, Fixture::default()).unwrap_err();
    assert_eq!(error.error, IoGroupCaptureError::Finished);
}

#[test]
fn dropped_capture_and_caught_provider_panic_refuse_whole_group() {
    let group = IoRecordingGroup::new(limits());
    let a = group.register(9, Fixture::default()).unwrap();
    drop(a);
    assert!(matches!(group.finish(), Err(IoGroupCaptureError::AbandonedStream(9))));
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(2, Fixture { panic: true, ..Fixture::default() }).unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read(&mut a, 1, Waker::noop())));
    assert!(failure.is_err());
    a.into_inner();
    assert!(matches!(group.finish(), Err(IoGroupCaptureError::InterruptedPoll(2))));
}

#[test]
fn abandoning_a_replay_prerequisite_wakes_and_invalidates_its_peer() {
    let replay = two_reads().replay();
    let a = replay.open(41).unwrap();
    let mut b = replay.open(73).unwrap();
    let (counter, waker) = counting();
    assert!(read(&mut b, 1, &waker).is_pending());
    drop(a);
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(matches!(read(&mut b, 1, &waker), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::AbandonedStream { stream: 41, remaining: 1 }
    )));
}

#[test]
fn duplicate_missing_and_reopened_streams_never_invent_a_provider() {
    let mut bound = limits(); bound.max_streams = 1;
    let group = IoRecordingGroup::new(bound);
    let a = group.register(u64::MAX, Fixture::default()).unwrap();
    let original = Fixture::new(b"retained");
    let counter = Arc::clone(&original.polls);
    let error = group.register(u64::MAX, original).unwrap_err();
    assert_eq!(error.error, IoGroupCaptureError::DuplicateStream(u64::MAX));
    assert!(Arc::ptr_eq(&counter, &error.io.polls));
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(group.register(0, error.io).unwrap_err().error, IoGroupCaptureError::Limit("streams"));
    a.into_inner();
    let replay = group.finish().unwrap().replay();
    assert!(matches!(replay.open(0), Err(IoGroupOpenError::UnknownStream(0))));
    let a = replay.open(u64::MAX).unwrap(); drop(a);
    assert!(matches!(replay.open(u64::MAX), Err(IoGroupOpenError::AlreadyOpened(u64::MAX))));
    replay.verify_complete().unwrap();
}

#[test]
fn vectored_write_flush_shutdown_and_eof_keep_exact_component_semantics() {
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(11, Fixture::default()).unwrap();
    let vectors = [IoSlice::new(b"a"), IoSlice::new(b""), IoSlice::new(b"bc")];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(a.is_write_vectored());
    assert_eq!(ready_value(Pin::new(&mut a).poll_write_vectored(&mut cx, &vectors)), 3);
    ready_value(Pin::new(&mut a).poll_flush(&mut cx));
    ready_value(Pin::new(&mut a).poll_shutdown(&mut cx));
    assert!(ready_value(read(&mut a, 1, Waker::noop())).is_empty());
    let original = a.into_inner();
    assert_eq!((original.output.as_slice(), original.vector_calls), (&b"abc"[..], 1));
    let replay = group.finish().unwrap().replay();
    let mut a = replay.open(11).unwrap();
    assert!(a.is_write_vectored());
    assert_eq!(ready_value(Pin::new(&mut a).poll_write_vectored(&mut cx, &vectors)), 3);
    ready_value(Pin::new(&mut a).poll_flush(&mut cx));
    ready_value(Pin::new(&mut a).poll_shutdown(&mut cx));
    assert!(ready_value(read(&mut a, 1, Waker::noop())).is_empty());
    replay.verify_complete().unwrap();
    assert!(matches!(read(&mut a, 1, Waker::noop()), Poll::Ready(Err(_))));
    assert!(replay.verify_complete().is_err());
}

struct LockProbe { shared: Arc<CaptureShared> }
impl AsyncWrite for LockProbe {
    fn is_write_vectored(&self) -> bool {
        assert!(self.shared.state.try_lock().is_some(), "capability callback under capture lock"); false
    }
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        assert!(self.shared.state.try_lock().is_some(), "provider callback under capture lock");
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
impl Drop for LockProbe {
    fn drop(&mut self) { assert!(self.shared.state.try_lock().is_some(), "provider destructor under capture lock"); }
}
#[test]
fn capture_does_not_invoke_provider_or_retirement_callbacks_under_group_lock() {
    let group = IoRecordingGroup::new(limits());
    let mut a = group.register(1, LockProbe { shared: Arc::clone(&group.shared) }).unwrap();
    ready_value(write(&mut a, b"data"));
    drop(a.into_inner());
    group.finish().unwrap();
}

#[test]
fn overlapping_stream_owners_capture_one_complete_observation_order() {
    let group = IoRecordingGroup::new(limits());
    let start = Arc::new(std::sync::Barrier::new(4));
    let mut workers = Vec::new();
    for id in 0..4 {
        let mut io = group.register(id, Fixture::default()).unwrap();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            start.wait();
            for _ in 0..16 { ready_value(write(&mut io, &[id as u8])); }
            io.into_inner()
        }));
    }
    for worker in workers { assert_eq!(worker.join().unwrap().output.len(), 16); }
    let tape = group.finish().unwrap();
    assert_eq!((tape.streams(), tape.operations()), (4, 64));
    let order = tape.order.clone();
    let ids: Vec<_> = tape.stream_ids().collect();
    let replay = tape.replay();
    let mut streams: Vec<_> = ids.iter().map(|id| replay.open(*id).unwrap()).collect();
    for entry in order {
        assert_eq!(entry.operation, IoOperation::Write);
        assert_eq!(ready_value(write(&mut streams[entry.stream], &[ids[entry.stream] as u8])), 1);
    }
    replay.verify_complete().unwrap();
}

struct ReentrantWake { shared: Arc<ReplayShared>, called: Arc<AtomicUsize>, panic: bool }
impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        assert!(self.shared.state.try_lock().is_some(), "wake under replay lock");
        self.called.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "hostile replay wake");
    }
}
#[test]
fn failure_wake_fanout_is_reentrant_and_one_panic_does_not_strand_another_stream() {
    let group = IoRecordingGroup::new(limits());
    for id in 0..3 {
        let mut stream = group.register(id, Fixture::new(b"x")).unwrap();
        ready_value(read(&mut stream, 1, Waker::noop())); stream.into_inner();
    }
    let replay = group.finish().unwrap().replay();
    let a = replay.open(0).unwrap();
    let mut b = replay.open(1).unwrap();
    let mut c = replay.open(2).unwrap();
    let called = Arc::new(AtomicUsize::new(0));
    for (stream, panic) in [(&mut b, true), (&mut c, false)] {
        let waker = Waker::from(Arc::new(ReentrantWake { shared: Arc::clone(&replay.shared), called: Arc::clone(&called), panic }));
        assert!(read(stream, 1, &waker).is_pending());
    }
    drop(a);
    assert_eq!(called.load(Ordering::SeqCst), 2);
    assert!(matches!(read(&mut b, 1, Waker::noop()), Poll::Ready(Err(_))));
    assert!(matches!(read(&mut c, 1, Waker::noop()), Poll::Ready(Err(_))));
}

#[test]
fn unused_stream_tail_and_latest_waiter_are_both_accounted() {
    let replay = two_reads().replay();
    let mut a = replay.open(41).unwrap();
    let mut b = replay.open(73).unwrap();
    let (old, old_waker) = counting(); let (new, new_waker) = counting();
    assert!(read(&mut b, 1, &old_waker).is_pending());
    assert!(read(&mut b, 1, &new_waker).is_pending());
    ready_value(read(&mut a, 1, Waker::noop()));
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert_eq!(new.0.load(Ordering::SeqCst), 1);
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Remaining(1)));
    ready_value(read(&mut b, 1, Waker::noop()));
    replay.verify_complete().unwrap();
}
