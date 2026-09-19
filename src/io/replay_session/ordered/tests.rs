use super::*;
use super::super::tests::{drive, exchange};
use crate::io::replay::IoCaptureLimits;
use crate::time::VirtualClock;
use crate::util::{ArenaIndex, DetEntropy};
use crate::util::entropy_replay::EntropyCaptureLimits;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

struct Pipe {
    offset: usize,
    written: Vec<u8>,
    calls: Arc<AtomicUsize>,
    pending: bool,
    reset: bool,
}
impl Pipe {
    fn new() -> Self {
        Self { offset: 0, written: Vec::new(), calls: Arc::new(AtomicUsize::new(0)), pending: false, reset: false }
    }
}
impl AsyncRead for Pipe {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.calls.fetch_add(1, Ordering::Relaxed);
        if this.pending { this.pending = false; cx.waker().wake_by_ref(); return Poll::Pending; }
        if this.reset { return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())); }
        let input = b"\x03\0\0\0yes";
        let count = buf.remaining().min(2).min(input.len() - this.offset);
        buf.put_slice(&input[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Pipe {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.calls.fetch_add(1, Ordering::Relaxed);
        let count = bytes.len().min(3);
        this.written.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn bounds() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(100, 1024, 4096, 8),
        entropy: EntropyCaptureLimits::new(100, 1024, 8),
        clock_observations: 100,
    }
}
fn capture(max_effects: usize) -> OrderedRecordingSession<Pipe, VirtualClock> {
    OrderedRecordingSession::new(Pipe::new(), Arc::new(DetEntropy::new(42)), Arc::new(VirtualClock::new()), bounds(), max_effects).unwrap()
}
fn value<T>(poll: Poll<io::Result<T>>) -> io::Result<T> {
    match poll { Poll::Ready(result) => result, Poll::Pending => panic!("unexpected pending") }
}
fn cx() -> Context<'static> { Context::from_waker(Waker::noop()) }
fn task(index: u32, generation: u32) -> TaskId { TaskId::from_arena(ArenaIndex::new(index, generation)) }

pub(super) fn recorded_exchange() -> OrderedRecordedSession {
    let mut recording = capture(100);
    let entropy = recording.entropy();
    let clock = recording.clock();
    assert_eq!(drive(exchange(recording.io(), entropy.as_ref(), clock.as_ref())).unwrap(), b"yes");
    recording.into_parts().1.unwrap()
}

#[test]
fn same_real_consumer_replays_ordered_partial_io_entropy_and_clock() {
    let pipe = Pipe::new();
    let calls = Arc::clone(&pipe.calls);
    let mut recording = OrderedRecordingSession::new(pipe, Arc::new(DetEntropy::new(42)), Arc::new(VirtualClock::new()), bounds(), 100).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let entropy = recording.entropy();
    let clock = recording.clock();
    let original = drive(exchange(recording.io(), entropy.as_ref(), clock.as_ref())).unwrap();
    let (pipe, session) = recording.into_parts();
    assert_eq!(pipe.written.len(), 16);
    drop(pipe);
    drop(entropy);
    drop(clock);
    let session = session.unwrap();
    assert!(session.effects() > 8);
    let before = calls.load(Ordering::Relaxed);
    let replayed = drive(session.replay().run(100, |p| exchange(p.io, p.entropy, p.clock))).unwrap().unwrap();
    assert_eq!(replayed, original);
    assert_eq!(calls.load(Ordering::Relaxed), before);
}

#[test]
fn negative_control_independent_windows_accept_swap_but_ordered_replay_refuses_it() {
    let independent = RecordingSession::new(Pipe::new(), Arc::new(DetEntropy::new(42)), Arc::new(VirtualClock::new()), bounds()).unwrap();
    independent.entropy().next_u64();
    independent.clock().now();
    drive(independent.into_parts().1.unwrap().replay().run(1, |p| Box::pin(async move {
        p.clock.try_now().unwrap();
        p.entropy.try_next_u64().unwrap();
    }))).unwrap();

    let recording = capture(10);
    recording.entropy().next_u64();
    recording.clock().now();
    let error = drive(recording.into_parts().1.unwrap().replay().run(1, |p| Box::pin(async move {
        let error = p.clock.try_now().unwrap_err();
        assert_eq!(error.expected, Some(OrderedEffect::Entropy(0)));
        assert_eq!(error.actual, OrderedEffect::Clock);
        assert_eq!(error, p.entropy.try_next_u64().unwrap_err());
    }))).unwrap_err();
    assert!(matches!(error, OrderedRunError::Replay(OrderedReplayError {
        order: Some(OrderCompletionError::Diverged(OrderReplayError { index: 0, reason: OrderReplayMismatch::Effect, .. })), ..
    })));
}

struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
}

#[test]
fn early_io_waits_without_progress_then_clock_completion_wakes_it() {
    let mut recording = capture(10);
    recording.clock().now();
    let mut bytes = [0; 2];
    value(Pin::new(recording.io()).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).unwrap();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let probe = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&probe));
    let mut ctx = Context::from_waker(&waker);
    let p = replay.inputs();
    let mut bytes = [0xa5; 2];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(Pin::new(&mut *p.io).poll_read(&mut ctx, &mut buf).is_pending());
    assert!(buf.filled().is_empty());
    assert_eq!(probe.0.load(Ordering::Relaxed), 0);
    assert_eq!(p.clock.try_now().unwrap(), Time::ZERO);
    assert_eq!(probe.0.load(Ordering::Relaxed), 1);
    value(Pin::new(&mut *p.io).poll_read(&mut ctx, &mut buf)).unwrap();
    assert_eq!(buf.filled(), &[3, 0]);
    replay.verify_complete().unwrap();
}

#[test]
fn source_ordinals_prevent_reordering_identical_requests_across_forks() {
    let recording = capture(20);
    let a = recording.entropy().fork(task(1, 4));
    let b = recording.entropy().fork(task(2, 4));
    a.next_u64();
    b.next_u64();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let p = replay.inputs();
    let a = p.entropy.try_fork(task(1, 4)).unwrap();
    let b = p.entropy.try_fork(task(2, 4)).unwrap();
    let error = b.try_next_u64().unwrap_err();
    assert_eq!(error.expected, Some(OrderedEffect::Entropy(1)));
    assert_eq!(error.actual, OrderedEffect::Entropy(2));
    assert_eq!(a.try_next_u64().unwrap_err(), error);
    assert!(replay.verify_complete().is_err());
}

#[test]
fn nested_forks_keep_global_creation_order_and_exact_values() {
    let recording = capture(20);
    let child = recording.entropy().fork(task(1, 4));
    let nested = child.fork(task(2, 5));
    let x = nested.next_u64();
    let time = recording.clock().now();
    let y = child.next_u64();
    let result = drive(recording.into_parts().1.unwrap().replay().run(10, |p| Box::pin(async move {
        let child = p.entropy.try_fork(task(1, 4)).unwrap();
        let nested = child.try_fork(task(2, 5)).unwrap();
        (nested.try_next_u64().unwrap(), p.clock.try_now().unwrap(), child.try_next_u64().unwrap())
    }))).unwrap();
    assert_eq!(result, (x, time, y));
}

#[test]
fn component_mismatch_poisoning_reaches_clock_io_and_all_entropy_clones() {
    let recording = capture(10);
    recording.entropy().next_u64();
    recording.clock().now();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let p = replay.inputs();
    let mut bytes = [0xa5; 8];
    let error = p.entropy.try_fill_bytes(&mut bytes).unwrap_err();
    assert_eq!(bytes, [0xa5; 8]);
    assert_eq!(error.reason, OrderReplayMismatch::Component);
    assert_eq!(p.clock.try_now().unwrap_err(), error);
    assert_eq!(p.entropy.clone().try_next_u64().unwrap_err(), error);
    assert!(value(Pin::new(&mut *p.io).poll_flush(&mut cx())).is_err());
    assert_eq!(p.clock.inner.observations_consumed(), 0);
    assert!(replay.verify_complete().is_err());
}

#[test]
fn captured_connection_error_is_not_misclassified_as_replay_divergence() {
    let mut pipe = Pipe::new(); pipe.reset = true;
    let mut recording = OrderedRecordingSession::new(pipe, Arc::new(DetEntropy::new(42)), Arc::new(VirtualClock::new()), bounds(), 10).unwrap();
    let mut bytes = [0; 2];
    assert_eq!(value(Pin::new(recording.io()).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    let mut replay = recording.into_parts().1.unwrap().replay();
    assert_eq!(value(Pin::new(replay.inputs().io).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    replay.verify_complete().unwrap();
}

#[test]
fn order_bound_refuses_capture_without_changing_the_live_exchange() {
    let mut recording = capture(1);
    let entropy = recording.entropy(); let clock = recording.clock();
    assert_eq!(drive(exchange(recording.io(), entropy.as_ref(), clock.as_ref())).unwrap(), b"yes");
    let (pipe, error) = recording.into_parts();
    assert_eq!(pipe.written.len(), 16);
    let error = error.unwrap_err();
    assert_eq!(error.order, Some(OrderCaptureError::Limit));
    assert_eq!(error.components, None);
}

#[test]
fn pending_io_does_not_spend_a_zero_effect_capture_budget() {
    let mut pipe = Pipe::new(); pipe.pending = true;
    let mut recording = OrderedRecordingSession::new(pipe, Arc::new(DetEntropy::new(42)), Arc::new(VirtualClock::new()), bounds(), 0).unwrap();
    let mut bytes = [0; 2];
    assert!(Pin::new(recording.io()).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes)).is_pending());
    let session = recording.into_parts().1.unwrap();
    assert_eq!(session.effects(), 0);
    session.replay().verify_complete().unwrap();
}

struct ReentrantClock { entropy: Mutex<Option<Arc<OrderedRecordingEntropy>>> }
impl TimeSource for ReentrantClock {
    fn now(&self) -> Time {
        let entropy = self.entropy.lock().clone().unwrap();
        entropy.next_u64();
        Time::from_nanos(77)
    }
}
#[test]
fn reentrant_provider_call_is_forwarded_but_capture_fails_without_deadlock() {
    let clock = Arc::new(ReentrantClock { entropy: Mutex::new(None) });
    let recording = OrderedRecordingSession::new(Pipe::new(), Arc::new(DetEntropy::new(42)), Arc::clone(&clock), bounds(), 10).unwrap();
    *clock.entropy.lock() = Some(recording.entropy());
    assert_eq!(recording.clock().now(), Time::from_nanos(77));
    assert_eq!(recording.into_parts().1.unwrap_err().order, Some(OrderCaptureError::Overlap));
}

struct PanickingClock(AtomicBool);
impl TimeSource for PanickingClock {
    fn now(&self) -> Time {
        assert!(self.0.swap(true, Ordering::Relaxed), "clock sentinel");
        Time::ZERO
    }
}
#[test]
fn caught_source_panic_cannot_publish_a_partial_order() {
    let recording = OrderedRecordingSession::new(Pipe::new(), Arc::new(DetEntropy::new(42)), Arc::new(PanickingClock(AtomicBool::new(false))), bounds(), 10).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| recording.clock().now())).is_err());
    assert_eq!(recording.clock().now(), Time::ZERO);
    let error = recording.into_parts().1.unwrap_err();
    assert_eq!(error.order, Some(OrderCaptureError::Interrupted));
    assert!(error.components.is_some());
}

struct InspectWake { order: Arc<ReplayOrder>, calls: Arc<AtomicUsize>, panic: bool }
impl Wake for InspectWake {
    fn wake(self: Arc<Self>) {
        let _ = self.order.verify(); // Would deadlock if callbacks ran under the order mutex.
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert!(!self.panic, "waker sentinel");
    }
}
#[test]
fn divergence_wakes_both_directions_even_when_one_callback_panics_and_reenters() {
    let recording = capture(10); recording.clock().now();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let calls = Arc::new(AtomicUsize::new(0));
    let read = Waker::from(Arc::new(InspectWake { order: Arc::clone(&replay.order), calls: Arc::clone(&calls), panic: true }));
    let write = Waker::from(Arc::new(InspectWake { order: Arc::clone(&replay.order), calls: Arc::clone(&calls), panic: false }));
    let p = replay.inputs(); let mut bytes = [0; 2];
    assert!(Pin::new(&mut *p.io).poll_read(&mut Context::from_waker(&read), &mut ReadBuf::new(&mut bytes)).is_pending());
    assert!(Pin::new(&mut *p.io).poll_write(&mut Context::from_waker(&write), b"x").is_pending());
    assert!(p.entropy.try_next_u64().is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(replay.verify_complete().is_err());
}

#[test]
fn same_direction_operation_changes_fail_instead_of_waiting_forever() {
    let mut recording = capture(10);
    value(Pin::new(recording.io()).poll_write(&mut cx(), b"abc")).unwrap();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let error = value(Pin::new(replay.inputs().io).poll_flush(&mut cx())).unwrap_err();
    assert_eq!(error.get_ref().unwrap().downcast_ref::<OrderReplayError>().unwrap().reason, OrderReplayMismatch::Effect);
}

struct DropClock<'a>(&'a OrderedReplayClock);
impl std::future::Future for DropClock<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { Poll::Ready(()) }
}
impl Drop for DropClock<'_> { fn drop(&mut self) { let _ = self.0.try_now(); } }
#[test]
fn consumer_future_destructor_is_inside_the_verified_window() {
    let recording = capture(10); recording.clock().now();
    drive(recording.into_parts().1.unwrap().replay().run(1, |p| Box::pin(DropClock(p.clock)))).unwrap();
    let error = drive(capture(10).into_parts().1.unwrap().replay().run(1, |p| Box::pin(DropClock(p.clock)))).unwrap_err();
    assert!(matches!(error, OrderedRunError::Replay(OrderedReplayError { order: Some(OrderCompletionError::Diverged(_)), .. })));
}

#[test]
fn zero_poll_budget_refuses_before_factory_and_unused_effects_refuse_output() {
    let calls = AtomicUsize::new(0);
    let error = drive(recorded_exchange().replay().run(0, |_| {
        calls.fetch_add(1, Ordering::Relaxed); Box::pin(async {})
    })).unwrap_err();
    assert_eq!(error, OrderedRunError::PollLimit { limit: 0 });
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let error = drive(recorded_exchange().replay().run(1, |_| Box::pin(async { 42 }))).unwrap_err();
    assert!(matches!(error, OrderedRunError::Replay(OrderedReplayError { order: Some(OrderCompletionError::Remaining { .. }), .. })));
}

#[test]
fn interrupted_replay_admission_is_sticky_and_unconsumed() {
    let order = ReplayOrder::new(OrderTape { entries: vec![gate::Entry { effect: OrderedEffect::Clock, child: 0, pending: None }], poll_aware: false });
    drop(order.enter(OrderedEffect::Clock).unwrap());
    let error = match order.enter(OrderedEffect::Clock) { Err(error) => error, Ok(_) => panic!("poisoned admission") };
    assert_eq!(error.index, 0);
    assert_eq!(error.reason, OrderReplayMismatch::Interrupted);
    assert_eq!(order.verify(), Err(OrderCompletionError::Diverged(error)));
}

#[test]
fn overlapping_capture_and_finish_in_flight_never_return_partial_order() {
    let order = RecordOrder::new(10);
    let guard = order.begin().unwrap();
    assert!(order.begin().is_none());
    guard.finish(OrderedEffect::Clock, true);
    assert!(matches!(order.finish(), Err(OrderCaptureError::Overlap)));
    let order = RecordOrder::new(10);
    let guard = order.begin().unwrap();
    assert!(matches!(order.finish(), Err(OrderCaptureError::InFlight)));
    guard.finish(OrderedEffect::Clock, true);
    assert!(matches!(order.finish(), Err(OrderCaptureError::Finished)));
}

#[test]
fn dropping_io_releases_parked_wakers_even_if_entropy_clones_survive() {
    let recording = capture(10); recording.clock().now();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let entropy = replay.inputs().entropy.clone();
    let probe = Arc::new(CountWake(AtomicUsize::new(0)));
    let weak = Arc::downgrade(&probe);
    let waker = Waker::from(probe);
    let mut bytes = [0; 2];
    assert!(Pin::new(replay.inputs().io).poll_read(&mut Context::from_waker(&waker), &mut ReadBuf::new(&mut bytes)).is_pending());
    drop(waker);
    assert!(weak.upgrade().is_some());
    drop(replay);
    assert!(weak.upgrade().is_none());
    drop(entropy);
}
