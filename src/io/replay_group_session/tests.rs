use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Wake;

#[derive(Default)]
struct Clock(AtomicU64);
impl TimeSource for Clock {
    fn now(&self) -> Time { Time::from_nanos(self.0.fetch_add(1, Ordering::SeqCst)) }
}
#[derive(Default)]
struct Fixture { input: &'static [u8], output: Vec<u8>, pending: bool, error: bool }
impl AsyncRead for Fixture {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if std::mem::take(&mut this.pending) { return Poll::Pending; }
        if std::mem::take(&mut this.error) { return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())); }
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
        let before = this.output.len();
        for buf in bufs { this.output.extend_from_slice(buf); }
        Poll::Ready(Ok(this.output.len() - before))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn limits() -> GroupSessionCaptureLimits {
    GroupSessionCaptureLimits {
        max_streams: 3, max_effects: 64, per_stream: IoCaptureLimits::new(32, 4096, 4096, 8),
        entropy: EntropyCaptureLimits::new(32, 4096, 8), clock_observations: 32,
    }
}
fn recording(bound: GroupSessionCaptureLimits) -> RecordingGroupSession<Clock> {
    RecordingGroupSession::new(Arc::new(crate::util::DetEntropy::new(29)), Arc::new(Clock::default()), bound).unwrap()
}
fn read(io: &mut (impl AsyncRead + Unpin), n: usize, waker: &Waker) -> Poll<io::Result<Vec<u8>>> {
    let mut bytes = vec![0; n];
    let mut buf = ReadBuf::new(&mut bytes);
    Pin::new(io).poll_read(&mut Context::from_waker(waker), &mut buf).map(|result| result.map(|()| buf.filled().to_vec()))
}
fn write(io: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Poll<io::Result<usize>> {
    Pin::new(io).poll_write(&mut Context::from_waker(Waker::noop()), bytes)
}
fn value<T>(result: Poll<io::Result<T>>) -> T {
    match result { Poll::Ready(Ok(value)) => value, _ => panic!("expected successful captured completion") }
}
#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn counting() -> (Arc<Counter>, Waker) {
    let count = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

// Capture IO(A), Clock, Fork(root), Entropy(child), IO(B), Entropy(root).
fn capture() -> (RecordedGroupSession, TaskId, Time, u64, u64) {
    let session = recording(limits());
    let mut a = session.register(41, Fixture { input: b"a", ..Fixture::default() }).unwrap();
    let mut b = session.register(73, Fixture { input: b"b", ..Fixture::default() }).unwrap();
    assert_eq!(value(read(&mut a, 1, Waker::noop())), b"a");
    let time = session.clock().now();
    let task = TaskId::new_for_test(9, 3);
    let child = session.entropy().fork(task);
    let nonce = child.next_u64();
    assert_eq!(value(read(&mut b, 1, Waker::noop())), b"b");
    let tail = session.entropy().next_u64();
    a.into_inner(); b.into_inner();
    (session.finish().unwrap(), task, time, nonce, tail)
}

#[test]
fn two_connections_clock_and_fork_share_one_replay_order() {
    let (tape, task, time, nonce, tail) = capture();
    assert_eq!(tape.stream_ids().collect::<Vec<_>>(), [41, 73]);
    assert_eq!(tape.effects(), 6);
    let replay = tape.replay();
    let mut b = replay.open(73).unwrap();
    let mut a = replay.open(41).unwrap();
    let (count, waker) = counting();
    assert!(read(&mut b, 1, &waker).is_pending());
    value(read(&mut a, 1, Waker::noop()));
    assert_eq!(count.0.load(Ordering::SeqCst), 0, "B must still wait for clock and entropy");
    assert_eq!(replay.clock().try_now().unwrap(), time);
    let child = replay.entropy().try_fork(task).unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(child.try_next_u64().unwrap(), nonce);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(value(read(&mut b, 1, &waker)), b"b");
    assert_eq!(replay.entropy().try_next_u64().unwrap(), tail);
    drop(a); drop(b);
    replay.verify_complete().unwrap();
}

#[test]
fn early_clock_is_sticky_and_wakes_every_parked_stream() {
    let (tape, _, _, _, _) = capture();
    let replay = tape.replay();
    let mut b = replay.open(73).unwrap();
    let (count, waker) = counting();
    assert!(read(&mut b, 1, &waker).is_pending());
    let first = replay.clock().try_now().unwrap_err();
    assert_eq!(first.index, 0);
    assert_eq!(first.reason, GroupReplayMismatch::Effect);
    assert_eq!(first.expected, Some(GroupEffect::Io { stream: 41, operation: IoOperation::Read }));
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(matches!(read(&mut b, 1, &waker), Poll::Ready(Err(_))));
    assert_eq!(replay.entropy().try_next_u64(), Err(first));
    assert_eq!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(first)));
}

#[test]
fn wrong_entropy_fork_generation_and_shape_invalidate_the_group() {
    for wrong_generation in [false, true] {
        let (tape, task, _, _, _) = capture();
        let replay = tape.replay();
        let mut a = replay.open(41).unwrap();
        value(read(&mut a, 1, Waker::noop()));
        replay.clock().try_now().unwrap();
        let error = if wrong_generation {
            replay.entropy().try_fork(TaskId::new_for_test(9, 4)).unwrap_err()
        } else {
            let child = replay.entropy().try_fork(task).unwrap();
            child.try_fill_bytes(&mut [0; 8]).unwrap_err()
        };
        assert_eq!(error.reason, GroupReplayMismatch::Component);
        assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    }
}

#[test]
fn omitted_unopened_stream_or_entropy_tail_never_passes() {
    let (tape, task, _, _, _) = capture();
    let replay = tape.replay();
    let mut a = replay.open(41).unwrap();
    value(read(&mut a, 1, Waker::noop()));
    replay.clock().try_now().unwrap();
    replay.entropy().try_fork(task).unwrap().try_next_u64().unwrap();
    assert_eq!(replay.verify_complete(), Err(GroupSessionCompletionError::Remaining(2)));
    let mut b = replay.open(73).unwrap();
    value(read(&mut b, 1, Waker::noop()));
    assert_eq!(replay.verify_complete(), Err(GroupSessionCompletionError::Remaining(1)));
}

#[test]
fn duplicate_and_excess_registration_return_original_providers() {
    let mut bound = limits(); bound.max_streams = 1;
    let session = recording(bound);
    let a = session.register(11, Fixture::default()).unwrap();
    let duplicate = session.register(11, Fixture { input: b"original", ..Fixture::default() }).unwrap_err();
    assert_eq!(duplicate.error, GroupSessionCaptureError::DuplicateStream(11));
    assert_eq!(duplicate.io.input, b"original");
    assert_eq!(session.register(12, Fixture::default()).unwrap_err().error, GroupSessionCaptureError::Limit("streams"));
    a.into_inner();
    session.finish().unwrap().replay().verify_complete().unwrap();
}

#[test]
fn finish_with_live_streams_is_retryable_and_does_not_finish_sources() {
    let session = recording(limits());
    let a = session.register(11, Fixture::default()).unwrap();
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::LiveStreams(1))));
    let time = session.clock().now();
    let entropy = session.entropy().next_u64();
    a.into_inner();
    let replay = session.finish().unwrap().replay();
    assert_eq!(replay.clock().try_now().unwrap(), time);
    assert_eq!(replay.entropy().try_next_u64().unwrap(), entropy);
    replay.verify_complete().unwrap();
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Finished)));
}

#[test]
fn every_capture_limit_refuses_whole_window_but_preserves_live_result() {
    for which in 0..4 {
        let mut bound = limits();
        match which {
            0 => bound.max_effects = 0,
            1 => bound.per_stream.max_operations = 0,
            2 => bound.entropy.max_calls = 0,
            _ => bound.clock_observations = 0,
        }
        let session = recording(bound);
        let mut a = session.register(1, Fixture::default()).unwrap();
        assert_eq!(value(write(&mut a, b"actual bytes")), 12);
        session.entropy().next_u64();
        session.clock().now();
        assert_eq!(a.into_inner().output, b"actual bytes");
        assert!(session.finish().is_err());
    }
}

#[test]
fn pending_io_is_not_a_completion_and_original_errors_are_observations() {
    let session = recording(limits());
    let mut a = session.register(1, Fixture { pending: true, error: true, ..Fixture::default() }).unwrap();
    assert!(read(&mut a, 4, Waker::noop()).is_pending());
    let time = session.clock().now();
    assert!(matches!(read(&mut a, 4, Waker::noop()), Poll::Ready(Err(_))));
    a.into_inner();
    let tape = session.finish().unwrap();
    assert_eq!(tape.effects(), 2);
    let replay = tape.replay();
    let mut a = replay.open(1).unwrap();
    assert!(read(&mut a, 4, Waker::noop()).is_pending());
    assert_eq!(replay.clock().try_now().unwrap(), time);
    assert!(matches!(read(&mut a, 4, Waker::noop()), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset));
    replay.verify_complete().unwrap();
}

#[test]
fn abandoned_capture_and_replay_streams_fail_closed() {
    let session = recording(limits());
    drop(session.register(1, Fixture::default()).unwrap());
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::AbandonedStream(1))));
    let (tape, _, _, _, _) = capture();
    let replay = tape.replay();
    let a = replay.open(41).unwrap();
    let mut b = replay.open(73).unwrap();
    let (count, waker) = counting();
    assert!(read(&mut b, 1, &waker).is_pending());
    drop(a);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(GroupSessionReplayError { reason: GroupReplayMismatch::AbandonedStream, .. }))));
}

#[test]
fn exhausted_stream_fails_immediately_even_before_other_effects_complete() {
    let (tape, _, _, _, _) = capture();
    let replay = tape.replay();
    let mut a = replay.open(41).unwrap();
    value(read(&mut a, 1, Waker::noop()));
    assert!(matches!(read(&mut a, 1, Waker::noop()), Poll::Ready(Err(_))));
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(GroupSessionReplayError { reason: GroupReplayMismatch::Exhausted, index: 1, .. }))));
}

#[test]
fn changed_write_and_same_stream_operation_are_not_parked_forever() {
    for wrong_kind in [false, true] {
        let session = recording(limits());
        let mut a = session.register(1, Fixture::default()).unwrap();
        value(write(&mut a, b"auth-request")); a.into_inner();
        let replay = session.finish().unwrap().replay();
        let mut a = replay.open(1).unwrap();
        let failed = if wrong_kind {
            matches!(Pin::new(&mut a).poll_flush(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_)))
        } else { matches!(write(&mut a, b"evil-request"), Poll::Ready(Err(_))) };
        assert!(failed);
        assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    }
}

#[test]
fn vectored_write_flush_shutdown_and_eof_consume_exact_turns() {
    let session = recording(limits());
    let mut a = session.register(1, Fixture::default()).unwrap();
    let bufs = [IoSlice::new(b"ab"), IoSlice::new(b""), IoSlice::new(b"c")];
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(value(Pin::new(&mut a).poll_write_vectored(&mut cx, &bufs)), 3);
    session.clock().now();
    value(Pin::new(&mut a).poll_flush(&mut cx));
    value(Pin::new(&mut a).poll_shutdown(&mut cx));
    assert!(value(read(&mut a, 4, Waker::noop())).is_empty());
    a.into_inner();
    let replay = session.finish().unwrap().replay();
    let mut a = replay.open(1).unwrap();
    assert!(a.is_write_vectored());
    assert_eq!(value(Pin::new(&mut a).poll_write_vectored(&mut cx, &bufs)), 3);
    assert!(Pin::new(&mut a).poll_flush(&mut cx).is_pending());
    replay.clock().try_now().unwrap();
    value(Pin::new(&mut a).poll_flush(&mut cx));
    value(Pin::new(&mut a).poll_shutdown(&mut cx));
    assert!(value(read(&mut a, 4, Waker::noop())).is_empty());
    replay.verify_complete().unwrap();
}

#[test]
fn latest_waiter_replaces_cancelled_operation_without_losing_prerequisite() {
    let (tape, task, _, _, _) = capture();
    let replay = tape.replay();
    let mut b = replay.open(73).unwrap();
    let mut a = replay.open(41).unwrap();
    let (old, old_waker) = counting(); let (new, new_waker) = counting();
    assert!(read(&mut b, 1, &old_waker).is_pending());
    assert!(read(&mut b, 1, &new_waker).is_pending());
    value(read(&mut a, 1, Waker::noop())); replay.clock().try_now().unwrap();
    replay.entropy().try_fork(task).unwrap().try_next_u64().unwrap();
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert_eq!(new.0.load(Ordering::SeqCst), 1);
    value(read(&mut b, 1, &new_waker)); replay.entropy().try_next_u64().unwrap();
    replay.verify_complete().unwrap();
}

#[test]
fn overlapping_live_effects_are_refused_without_replacing_values() {
    struct ReenterClock(Mutex<Option<Arc<GroupRecordingEntropy>>>);
    impl TimeSource for ReenterClock {
        fn now(&self) -> Time {
            let entropy = self.0.lock().take();
            entropy.unwrap().next_u64();
            Time::from_nanos(7)
        }
    }
    let clock = Arc::new(ReenterClock(Mutex::new(None)));
    let session = RecordingGroupSession::new(Arc::new(crate::util::DetEntropy::new(29)), Arc::clone(&clock), limits()).unwrap();
    *clock.0.lock() = Some(session.entropy());
    assert_eq!(session.clock().now(), Time::from_nanos(7));
    assert!(matches!(session.finish(), Err(GroupSessionCaptureError::Overlap)));
}

#[test]
fn consumer_output_is_gated_on_all_effects_and_zero_never_calls_factory() {
    let session = recording(limits()); session.clock().now();
    let replay = session.finish().unwrap().replay();
    let mut driver = Box::pin(replay.run(1, |session| Box::pin(async move {
        session.clock().try_now().unwrap();
        Err::<(), _>("original application failure")
    })));
    assert!(matches!(driver.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(Err("original application failure")))));

    let (tape, _, _, _, _) = capture();
    let mut driver = Box::pin(tape.replay().run(1, |_| Box::pin(async { "false success" })));
    assert!(matches!(driver.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(GroupSessionRunError::Replay(GroupSessionCompletionError::Remaining(6))))));

    let empty = recording(limits()).finish().unwrap().replay();
    let mut driver = Box::pin(empty.run::<(), _>(0, |_| panic!("zero budget factory sentinel")));
    assert!(matches!(driver.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(GroupSessionRunError::PollLimit { limit: 0 }))));
}

#[test]
fn infallible_clock_refusal_stays_sticky_after_caught_panic_and_debug_is_redacted() {
    let (tape, _, _, _, _) = capture();
    assert!(!format!("{tape:?}").contains("auth-request"));
    let replay = tape.replay();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| replay.clock().now()));
    assert!(caught.is_err());
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    fn bounds<T: Send + Sync + Unpin>() {}
    bounds::<GroupReplayIo>(); bounds::<GroupReplayClock>(); bounds::<GroupReplayEntropy>();
}
