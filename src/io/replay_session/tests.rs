use super::*;
use crate::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::types::{TaskId, Time};
use crate::util::{ArenaIndex, DetEntropy};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

pub(super) fn drive<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("test consumer did not complete");
}

#[derive(Debug)]
struct TestIo {
    response: Vec<u8>,
    offset: usize,
    written: Vec<u8>,
    polls: Arc<AtomicUsize>,
    fail_read: bool,
}

impl TestIo {
    fn new() -> Self {
        Self {
            response: vec![3, 0, 0, 0, b'y', b'e', b's'],
            offset: 0,
            written: Vec::new(),
            polls: Arc::new(AtomicUsize::new(0)),
            fail_read: false,
        }
    }
}

impl AsyncRead for TestIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::Relaxed);
        if this.fail_read {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let count = buf.remaining().min(2).min(this.response.len() - this.offset);
        buf.put_slice(&this.response[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::Relaxed);
        let count = bytes.len().min(3);
        this.written.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct TestClock {
    calls: AtomicUsize,
}

impl TimeSource for TestClock {
    fn now(&self) -> Time {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        Time::from_nanos(900 + call as u64)
    }
}

fn limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(100, 1024, 1024, 8),
        entropy: EntropyCaptureLimits::new(30, 1024, 8),
        clock_observations: 30,
    }
}

fn capture() -> RecordingSession<TestIo, TestClock> {
    RecordingSession::new(
        TestIo::new(),
        Arc::new(DetEntropy::new(42)),
        Arc::new(TestClock { calls: AtomicUsize::new(0) }),
        limits(),
    )
    .unwrap()
}

// The SAME consumer runs against live providers and replay providers. Its
// request depends on BOTH entropy and time; writes are accepted in short chunks.
pub(super) fn exchange<'a, I, E, C>(
    io: &'a mut I,
    entropy: &'a E,
    clock: &'a C,
) -> ReplayConsumerFuture<'a, io::Result<Vec<u8>>>
where
    I: AsyncRead + AsyncWrite + Unpin,
    E: EntropySource + ?Sized,
    C: TimeSource + ?Sized,
{
    Box::pin(async move {
        let nonce = entropy.next_u64();
        let now = clock.now();
        let mut request = [0; 16];
        request[..8].copy_from_slice(&nonce.to_le_bytes());
        request[8..].copy_from_slice(&now.as_nanos().to_le_bytes());
        io.write_all(&request).await?;
        io.flush().await?;
        let mut header = [0; 4];
        io.read_exact(&mut header).await?;
        let length = u32::from_le_bytes(header) as usize;
        if length > 128 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut body = vec![0; length];
        io.read_exact(&mut body).await?;
        io.shutdown().await?;
        Ok(body)
    })
}

pub(super) fn recorded_exchange() -> RecordedSession {
    let mut capture = capture();
    let entropy = capture.entropy();
    let clock = capture.clock();
    assert_eq!(drive(exchange(capture.io(), entropy.as_ref(), clock.as_ref())).unwrap(), b"yes");
    capture.into_parts().1.unwrap()
}

#[test]
fn same_async_consumer_replays_all_three_providers_without_source_access() {
    let clock = Arc::new(TestClock { calls: AtomicUsize::new(0) });
    let source = TestIo::new();
    let io_polls = Arc::clone(&source.polls);
    let mut capture = RecordingSession::new(
        source, Arc::new(DetEntropy::new(42)), Arc::clone(&clock), limits(),
    ).unwrap();
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);
    assert_eq!(io_polls.load(Ordering::Relaxed), 0);
    let entropy = capture.entropy();
    let recorded_clock = capture.clock();
    let original = drive(exchange(capture.io(), entropy.as_ref(), recorded_clock.as_ref())).unwrap();
    let (source, session) = capture.into_parts();
    assert_eq!(source.written.len(), 16);
    let session = session.unwrap();
    assert_eq!(session.entropy_calls(), 1);
    assert_eq!(session.clock_observations(), 1);
    assert!(session.io_operations() > 5);
    let polls_before = io_polls.load(Ordering::Relaxed);
    drop(source);
    drop(entropy);
    drop(recorded_clock);
    let replayed = drive(session.replay().run(100, |p| exchange(p.io, p.entropy, p.clock)))
        .unwrap().unwrap();
    assert_eq!(replayed, original);
    assert_eq!(io_polls.load(Ordering::Relaxed), polls_before);
    assert_eq!(clock.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn original_application_error_is_preserved_not_mistaken_for_replay_failure() {
    let mut source = TestIo::new();
    source.fail_read = true;
    let mut capture = RecordingSession::new(
        source, Arc::new(DetEntropy::new(42)),
        Arc::new(TestClock { calls: AtomicUsize::new(0) }), limits(),
    ).unwrap();
    let entropy = capture.entropy();
    let clock = capture.clock();
    let original = drive(exchange(capture.io(), entropy.as_ref(), clock.as_ref())).unwrap_err();
    let replay = capture.into_parts().1.unwrap().replay();
    let reproduced = drive(replay.run(100, |p| exchange(p.io, p.entropy, p.clock)))
        .unwrap().unwrap_err();
    assert_eq!(original.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(reproduced.kind(), original.kind());
}

#[test]
fn incomplete_consumer_reports_every_unconsumed_domain() {
    let replay = recorded_exchange().replay();
    let error = drive(replay.run(10, |_| Box::pin(async { 42 }))).unwrap_err();
    let SessionRunError::Replay(error) = error else { panic!("expected completion refusal") };
    assert!(error.io.is_some());
    assert!(error.entropy.is_some());
    assert!(error.clock.is_some());
}

#[test]
fn ignored_io_divergence_cannot_be_returned_as_success() {
    let error = drive(recorded_exchange().replay().run(10, |p| Box::pin(async move {
        p.entropy.try_next_u64().unwrap();
        p.clock.try_now().unwrap();
        let _ = p.io.write_all(b"wrong nonce and request").await;
        "consumer ignored the error"
    }))).unwrap_err();
    assert!(matches!(error, SessionRunError::Replay(SessionReplayError {
        io: Some(IoReplayCompletionError::Diverged(_)), ..
    })));
}

#[test]
fn ignored_entropy_and_clock_exhaustion_are_both_retained() {
    let empty = capture().into_parts().1.unwrap().replay();
    let error = drive(empty.run(10, |p| Box::pin(async move {
        let _ = p.entropy.try_next_u64();
        let _ = p.clock.try_now();
        true
    }))).unwrap_err();
    let SessionRunError::Replay(error) = error else { panic!("expected divergence") };
    assert!(error.io.is_none());
    assert!(matches!(error.entropy, Some(EntropyReplayCompletionError::Diverged(_))));
    assert!(matches!(error.clock, Some(TimeReplayError::Exhausted { index: 0 })));
}

#[test]
fn unused_forked_entropy_is_part_of_joint_completion() {
    let capture = capture();
    let task = TaskId::from_arena(ArenaIndex::new(7, 3));
    let child = capture.entropy().fork(task);
    child.next_u64();
    let replay = capture.into_parts().1.unwrap().replay();
    let error = drive(replay.run(10, move |p| Box::pin(async move {
        p.entropy.try_fork(task).unwrap();
    }))).unwrap_err();
    assert!(matches!(error, SessionRunError::Replay(SessionReplayError {
        entropy: Some(EntropyReplayCompletionError::Remaining { calls: 1 }), ..
    })));
}

#[test]
fn fork_generation_is_not_silently_remapped() {
    let capture = capture();
    capture.entropy().fork(TaskId::from_arena(ArenaIndex::new(7, 3)));
    let error = drive(capture.into_parts().1.unwrap().replay().run(10, |p| Box::pin(async move {
        let _ = p.entropy.try_fork(TaskId::from_arena(ArenaIndex::new(7, 4)));
    }))).unwrap_err();
    assert!(matches!(error, SessionRunError::Replay(SessionReplayError {
        entropy: Some(EntropyReplayCompletionError::Diverged(_)), ..
    })));
}

#[test]
fn capture_failures_preserve_live_results_and_original_io_owner() {
    let mut bounds = limits();
    bounds.io.max_operations = 0;
    bounds.entropy.max_calls = 0;
    bounds.clock_observations = 0;
    let mut capture = RecordingSession::new(
        TestIo::new(), Arc::new(DetEntropy::new(42)),
        Arc::new(TestClock { calls: AtomicUsize::new(0) }), bounds,
    ).unwrap();
    let entropy = capture.entropy();
    let clock = capture.clock();
    assert_eq!(drive(exchange(capture.io(), entropy.as_ref(), clock.as_ref())).unwrap(), b"yes");
    let (source, result) = capture.into_parts();
    assert_eq!(source.written.len(), 16);
    let error = result.unwrap_err();
    assert!(error.io.is_some());
    assert_eq!(error.entropy, Some(EntropyCaptureError::CallLimit));
    assert_eq!(error.clock, Some(TimeCaptureError::ObservationLimit));
}

#[test]
fn no_root_entropy_capacity_refuses_before_invoking_any_source() {
    let mut bounds = limits();
    bounds.entropy.max_streams = 0;
    let source = TestIo::new();
    let io_polls = Arc::clone(&source.polls);
    let clock = Arc::new(TestClock { calls: AtomicUsize::new(0) });
    let error = RecordingSession::new(
        source, Arc::new(DetEntropy::new(42)), Arc::clone(&clock), bounds,
    ).unwrap_err();
    assert_eq!(error, EntropyCaptureError::NoRootCapacity);
    assert_eq!(io_polls.load(Ordering::Relaxed), 0);
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn zero_poll_budget_does_not_invoke_consumer_factory() {
    let calls = AtomicUsize::new(0);
    let error = drive(capture().into_parts().1.unwrap().replay().run(0, |_| {
        calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async {})
    })).unwrap_err();
    assert_eq!(error, SessionRunError::PollLimit { limit: 0 });
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

struct PendingConsumer<'a> {
    polls: &'a AtomicUsize,
    drops: &'a AtomicUsize,
}

impl Future for PendingConsumer<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Drop for PendingConsumer<'_> {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::Relaxed); }
}

#[test]
fn poll_budget_bounds_driver_and_drops_owned_consumer_once() {
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let (p, d) = (Arc::clone(&polls), Arc::clone(&drops));
    let error = drive(capture().into_parts().1.unwrap().replay().run(3, move |_| {
        Box::pin(async move {
            PendingConsumer { polls: &p, drops: &d }.await;
        })
    })).unwrap_err();
    assert_eq!(error, SessionRunError::PollLimit { limit: 3 });
    assert_eq!(polls.load(Ordering::Relaxed), 3);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_driver_drops_pending_consumer_without_manufacturing_a_result() {
    let drops = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&drops);
    let mut driver = Box::pin(capture().into_parts().1.unwrap().replay().run(100, move |_| {
        Box::pin(async move {
            let polls = AtomicUsize::new(0);
            PendingConsumer { polls: &polls, drops: &d }.await;
        })
    }));
    assert!(driver.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(driver);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

struct ConsumeOnDrop<'a> { clock: &'a ReplayTimeSource }
impl Future for ConsumeOnDrop<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { Poll::Ready(()) }
}
impl Drop for ConsumeOnDrop<'_> {
    fn drop(&mut self) { let _ = self.clock.try_now(); }
}

#[test]
fn finalizer_observations_are_checked_after_dropping_consumer_future() {
    let capture = capture();
    capture.clock().now();
    let replay = capture.into_parts().1.unwrap().replay();
    drive(replay.run(1, |p| Box::pin(ConsumeOnDrop { clock: p.clock }))).unwrap();
    let empty = capture_empty();
    let error = drive(empty.run(1, |p| Box::pin(ConsumeOnDrop { clock: p.clock }))).unwrap_err();
    assert!(matches!(error, SessionRunError::Replay(SessionReplayError {
        clock: Some(TimeReplayError::Exhausted { .. }), ..
    })));
}

fn capture_empty() -> ReplaySession { capture().into_parts().1.unwrap().replay() }

#[test]
fn panics_propagate_instead_of_becoming_successful_replays() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drive(capture_empty().run(1, |_| Box::pin(async { panic!("consumer sentinel") })))
    }));
    assert!(result.is_err());
}

#[test]
fn debug_output_does_not_include_payloads_or_original_provider() {
    let mut source = TestIo::new();
    source.response = [4, 0, 0, 0, b'S', b'E', b'C', b'R'].to_vec();
    let mut capture = RecordingSession::new(
        source, Arc::new(DetEntropy::new(42)),
        Arc::new(TestClock { calls: AtomicUsize::new(0) }), limits(),
    ).unwrap();
    let entropy = capture.entropy();
    let clock = capture.clock();
    drive(exchange(capture.io(), entropy.as_ref(), clock.as_ref())).unwrap();
    let live_debug = format!("{capture:?}");
    let tape = capture.into_parts().1.unwrap();
    let tape_debug = format!("{tape:?}");
    let debug = format!("{tape_debug} {:?}", tape.replay());
    for text in [live_debug, debug] {
        assert!(!text.contains("SECR"));
        assert!(!text.contains("TestIo"));
        assert!(!text.contains("TestClock"));
    }
}
