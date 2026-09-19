use super::super::tests::{drive, exchange};
use super::*;
use crate::io::replay::{IoCaptureLimits, IoOperation};
use crate::io::{AsyncReadExt, AsyncWriteExt};
use crate::time::VirtualClock;
use crate::util::{DetEntropy, entropy_replay::EntropyCaptureLimits};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

pub(super) struct PendingPipe {
    polls: [usize; 5],
    offset: usize,
    written: Vec<u8>,
    reset: bool,
    panic: bool,
}
impl PendingPipe {
    fn new() -> Self {
        Self {
            polls: [0; 5],
            offset: 0,
            written: Vec::new(),
            reset: false,
            panic: false,
        }
    }
    fn pending(&mut self, operation: usize, cx: &Context<'_>) -> bool {
        assert!(!self.panic, "source poll sentinel");
        self.polls[operation] += 1;
        let pending = self.polls[operation] % 2 == 1;
        if pending {
            cx.waker().wake_by_ref();
        }
        pending
    }
}
impl AsyncRead for PendingPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending(0, cx) {
            return Poll::Pending;
        }
        if this.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let bytes = b"\x03\0\0\0yes";
        let count = buf.remaining().min(2).min(bytes.len() - this.offset);
        buf.put_slice(&bytes[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for PendingPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending(1, cx) {
            return Poll::Pending;
        }
        let count = bytes.len().min(3);
        this.written.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending(2, cx) {
            return Poll::Pending;
        }
        let bytes: Vec<u8> = bufs.iter().flat_map(|buf| buf.iter().copied()).collect();
        this.written.extend_from_slice(&bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.get_mut().pending(3, cx) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.get_mut().pending(4, cx) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
fn limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(256, 4096, 4096, 8),
        entropy: EntropyCaptureLimits::new(16, 128, 4),
        clock_observations: 16,
    }
}
fn with_limits(
    pending: PendingIoCaptureLimits,
    max_effects: usize,
) -> OrderedRecordingSession<PendingPipe, VirtualClock> {
    OrderedRecordingSession::new_with_pending_io(
        PendingPipe::new(),
        Arc::new(DetEntropy::new(42)),
        Arc::new(VirtualClock::new()),
        limits(),
        max_effects,
        pending,
    )
    .unwrap()
}
pub(super) fn capture() -> OrderedRecordingSession<PendingPipe, VirtualClock> {
    with_limits(PendingIoCaptureLimits::new(256, 4096, 8), 512)
}
fn cx() -> Context<'static> {
    Context::from_waker(Waker::noop())
}
fn value<T>(poll: Poll<io::Result<T>>) -> io::Result<T> {
    match poll {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("expected ready"),
    }
}
pub(super) fn recorded_exchange() -> OrderedRecordedSession {
    let mut recording = capture();
    let entropy = recording.entropy();
    let clock = recording.clock();
    assert_eq!(
        drive(exchange(recording.io(), entropy.as_ref(), clock.as_ref())).unwrap(),
        b"yes"
    );
    recording.into_parts().1.unwrap()
}

fn race_read<'a, I: AsyncRead + Unpin>(
    io: &'a mut I,
) -> ReplayConsumerFuture<'a, io::Result<bool>> {
    Box::pin(async move {
        let mut bytes = [0; 2];
        let io_won = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut bytes);
            // A ready alternative wins whenever the read suspends. Drain the
            // read afterward so BOTH branches consume the same completed tape.
            match Pin::new(&mut *io).poll_read(cx, &mut buf) {
                Poll::Pending => Poll::Ready(Ok(false)),
                Poll::Ready(result) => Poll::Ready(result.map(|()| true)),
            }
        })
        .await?;
        if !io_won {
            io.read_exact(&mut bytes).await?;
        }
        Ok(io_won)
    })
}

#[test]
fn negative_control_completed_only_replay_changes_race_winner_but_poll_aware_preserves_it() {
    let mut old = OrderedRecordingSession::new(
        PendingPipe::new(),
        Arc::new(DetEntropy::new(42)),
        Arc::new(VirtualClock::new()),
        limits(),
        512,
    )
    .unwrap();
    assert!(!drive(race_read(old.io())).unwrap());
    // This is the old mode's documented limitation, not an assertion weakened
    // to make the new path pass: all completions match but the winner changes.
    assert!(
        drive(
            old.into_parts()
                .1
                .unwrap()
                .replay()
                .run(16, |p| race_read(p.io))
        )
        .unwrap()
        .unwrap()
    );

    let mut recording = capture();
    assert!(!drive(race_read(recording.io())).unwrap());
    let tape = recording.into_parts().1.unwrap();
    assert!(tape.is_poll_aware());
    assert_eq!(tape.pending_io_polls(), 1);
    assert!(
        !drive(tape.replay().run(16, |p| race_read(p.io)))
            .unwrap()
            .unwrap()
    );
}

#[test]
fn all_io_operations_preserve_pending_boundaries_and_partial_progress() {
    let tape = recorded_exchange();
    assert!(tape.pending_io_polls() > 8);
    assert_eq!(
        drive(
            tape.replay()
                .run(100, |p| exchange(p.io, p.entropy, p.clock))
        )
        .unwrap()
        .unwrap(),
        b"yes"
    );
}

#[test]
fn pending_write_fingerprint_rejects_changed_bytes_and_poison_reaches_other_sources() {
    let mut recording = capture();
    assert!(
        Pin::new(recording.io())
            .poll_write(&mut cx(), b"secret")
            .is_pending()
    );
    let mut replay = recording.into_parts().1.unwrap().replay();
    let p = replay.inputs();
    let error = value(Pin::new(&mut *p.io).poll_write(&mut cx(), b"secreX")).unwrap_err();
    let error = *error
        .get_ref()
        .unwrap()
        .downcast_ref::<OrderReplayError>()
        .unwrap();
    assert_eq!(error.reason, OrderReplayMismatch::Component);
    assert_eq!(p.clock.try_now().unwrap_err(), error);
    assert_eq!(p.entropy.clone().try_next_u64().unwrap_err(), error);
    assert_eq!(p.io.inner.consumed_operations(), 0);
    assert!(replay.verify_complete().is_err());
}

#[test]
fn pending_read_checks_capacity_before_modifying_destination() {
    let mut recording = capture();
    let mut bytes = [0; 2];
    assert!(
        Pin::new(recording.io())
            .poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))
            .is_pending()
    );
    let mut replay = recording.into_parts().1.unwrap().replay();
    let mut changed = [0xa5; 3];
    let mut buf = ReadBuf::new(&mut changed);
    assert!(value(Pin::new(replay.inputs().io).poll_read(&mut cx(), &mut buf)).is_err());
    assert!(buf.filled().is_empty());
    assert_eq!(changed, [0xa5; 3]);
}

#[test]
fn pending_vectors_preserve_boundaries_even_with_identical_concatenated_bytes() {
    let original = [IoSlice::new(b"ab"), IoSlice::new(b"c")];
    let changed = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    let mut recording = capture();
    assert!(
        Pin::new(recording.io())
            .poll_write_vectored(&mut cx(), &original)
            .is_pending()
    );
    let mut replay = recording.into_parts().1.unwrap().replay();
    assert!(value(Pin::new(replay.inputs().io).poll_write_vectored(&mut cx(), &changed)).is_err());
    assert!(replay.verify_complete().is_err());
}

#[test]
fn empty_vectors_and_empty_slices_replay_without_fabricated_completion() {
    for lengths in [Vec::new(), vec![0], vec![0, 0, 0]] {
        let bufs: Vec<IoSlice<'_>> = lengths.iter().map(|_| IoSlice::new(b"")).collect();
        let mut recording = capture();
        assert!(
            Pin::new(recording.io())
                .poll_write_vectored(&mut cx(), &bufs)
                .is_pending()
        );
        let mut replay = recording.into_parts().1.unwrap().replay();
        assert!(
            Pin::new(replay.inputs().io)
                .poll_write_vectored(&mut cx(), &bufs)
                .is_pending()
        );
        assert_eq!(replay.inputs().io.inner.consumed_operations(), 0);
        replay.verify_complete().unwrap();
    }
}

#[test]
fn dropped_pending_attempts_keep_their_place_relative_to_entropy_and_clock() {
    let mut recording = capture();
    assert!(Pin::new(recording.io()).poll_flush(&mut cx()).is_pending());
    let random = recording.entropy().next_u64();
    let time = recording.clock().now();
    assert!(
        Pin::new(recording.io())
            .poll_shutdown(&mut cx())
            .is_pending()
    );
    let mut replay = recording.into_parts().1.unwrap().replay();
    let p = replay.inputs();
    assert!(Pin::new(&mut *p.io).poll_flush(&mut cx()).is_pending());
    assert_eq!(p.entropy.try_next_u64().unwrap(), random);
    assert_eq!(p.clock.try_now().unwrap(), time);
    assert!(Pin::new(&mut *p.io).poll_shutdown(&mut cx()).is_pending());
    replay.verify_complete().unwrap();
}

#[test]
fn unrecorded_early_io_is_a_divergence_in_poll_aware_mode_not_a_silent_wait() {
    let recording = capture();
    recording.clock().now();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let error = value(Pin::new(replay.inputs().io).poll_flush(&mut cx())).unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<OrderReplayError>()
            .unwrap()
            .reason,
        OrderReplayMismatch::Effect
    );
}

#[test]
fn unconsumed_pending_tail_prevents_success_even_with_empty_component_tapes() {
    let mut recording = capture();
    assert!(Pin::new(recording.io()).poll_flush(&mut cx()).is_pending());
    let replay = recording.into_parts().1.unwrap().replay();
    let error = drive(replay.run(1, |_| Box::pin(async {}))).unwrap_err();
    assert!(matches!(
        error,
        OrderedRunError::Replay(OrderedReplayError {
            order: Some(OrderCompletionError::Remaining { remaining: 1 }),
            components: None,
        })
    ));
}

#[test]
fn pending_limits_refuse_capture_but_never_change_live_results_or_ownership() {
    for (bounds, total, expected, vectored) in [
        (
            PendingIoCaptureLimits::new(0, 16, 8),
            10,
            OrderCaptureError::PendingLimit("polls"),
            false,
        ),
        (
            PendingIoCaptureLimits::new(10, 0, 8),
            10,
            OrderCaptureError::PendingLimit("write bytes"),
            false,
        ),
        (
            PendingIoCaptureLimits::new(10, 16, 0),
            10,
            OrderCaptureError::PendingLimit("vectored slices"),
            true,
        ),
        (
            PendingIoCaptureLimits::new(10, 16, 8),
            0,
            OrderCaptureError::Limit,
            false,
        ),
    ] {
        let mut recording = with_limits(bounds, total);
        if vectored {
            let bufs = [IoSlice::new(b"abc")];
            assert!(
                Pin::new(recording.io())
                    .poll_write_vectored(&mut cx(), &bufs)
                    .is_pending()
            );
            assert_eq!(
                value(Pin::new(recording.io()).poll_write_vectored(&mut cx(), &bufs)).unwrap(),
                3
            );
        } else {
            assert!(
                Pin::new(recording.io())
                    .poll_write(&mut cx(), b"abc")
                    .is_pending()
            );
            assert_eq!(
                value(Pin::new(recording.io()).poll_write(&mut cx(), b"abc")).unwrap(),
                3
            );
        }
        let (pipe, result) = recording.into_parts();
        assert_eq!(pipe.written, b"abc");
        assert_eq!(result.unwrap_err().order, Some(expected));
    }
}

#[test]
fn pending_byte_budget_is_aggregate_not_reset_by_successful_polls() {
    let mut recording = with_limits(PendingIoCaptureLimits::new(8, 5, 8), 32);
    assert!(
        Pin::new(recording.io())
            .poll_write(&mut cx(), b"abc")
            .is_pending()
    );
    value(Pin::new(recording.io()).poll_write(&mut cx(), b"abc")).unwrap();
    assert!(
        Pin::new(recording.io())
            .poll_write(&mut cx(), b"abc")
            .is_pending()
    );
    assert_eq!(
        recording.into_parts().1.unwrap_err().order,
        Some(OrderCaptureError::PendingLimit("write bytes"))
    );
}

#[test]
fn zero_pending_budget_still_allows_ready_io_and_empty_strict_windows() {
    let mut pipe = PendingPipe::new();
    pipe.polls[3] = 1;
    let mut recording = OrderedRecordingSession::new_with_pending_io(
        pipe,
        Arc::new(DetEntropy::new(42)),
        Arc::new(VirtualClock::new()),
        limits(),
        4,
        PendingIoCaptureLimits::new(0, 0, 0),
    )
    .unwrap();
    value(Pin::new(recording.io()).poll_flush(&mut cx())).unwrap();
    let tape = recording.into_parts().1.unwrap();
    assert!(tape.is_poll_aware());
    assert_eq!(tape.pending_io_polls(), 0);
    drive(
        tape.replay()
            .run(1, |p| Box::pin(async move { p.io.flush().await })),
    )
    .unwrap()
    .unwrap();
    let empty = with_limits(PendingIoCaptureLimits::new(0, 0, 0), 0)
        .into_parts()
        .1
        .unwrap();
    assert!(empty.is_poll_aware());
    empty.replay().verify_complete().unwrap();
}

#[test]
fn original_read_error_after_pending_remains_an_application_error() {
    let mut recording = capture();
    recording.io.inner = RecordingIo::new(
        PendingPipe {
            reset: true,
            ..PendingPipe::new()
        },
        limits().io,
    );
    let mut bytes = [0; 2];
    assert_eq!(
        drive(recording.io().read_exact(&mut bytes))
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionReset
    );
    let tape = recording.into_parts().1.unwrap();
    let result = drive(tape.replay().run(4, |p| {
        Box::pin(async move { p.io.read_exact(&mut [0; 2]).await })
    }))
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
}

struct Probe {
    order: Option<Arc<ReplayOrder>>,
    calls: AtomicUsize,
    panic: bool,
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        if let Some(order) = &self.order {
            let _ = order.verify();
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert!(!self.panic, "wake sentinel");
    }
}
#[test]
fn recorded_pending_wakes_once_outside_locks_and_contains_callback_panics() {
    let mut recording = capture();
    let live = Arc::new(Probe {
        order: None,
        calls: AtomicUsize::new(0),
        panic: false,
    });
    let waker = Waker::from(Arc::clone(&live));
    assert!(
        Pin::new(recording.io())
            .poll_flush(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(live.calls.load(Ordering::Relaxed), 1); // Capture added no wake.
    value(Pin::new(recording.io()).poll_flush(&mut cx())).unwrap();
    let mut replay = recording.into_parts().1.unwrap().replay();
    let probe = Arc::new(Probe {
        order: Some(Arc::clone(&replay.order)),
        calls: AtomicUsize::new(0),
        panic: true,
    });
    let waker = Waker::from(Arc::clone(&probe));
    assert!(
        Pin::new(replay.inputs().io)
            .poll_flush(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(probe.calls.load(Ordering::Relaxed), 1);
    value(Pin::new(replay.inputs().io).poll_flush(&mut cx())).unwrap();
    replay.verify_complete().unwrap();
}

#[test]
fn captured_source_unwind_never_publishes_a_poll_prefix() {
    let mut recording = capture();
    recording.io.inner = RecordingIo::new(
        PendingPipe {
            panic: true,
            ..PendingPipe::new()
        },
        limits().io,
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Pin::new(recording.io()).poll_flush(&mut cx());
        }))
        .is_err()
    );
    let error = recording.into_parts().1.unwrap_err();
    assert_eq!(error.order, Some(OrderCaptureError::Interrupted));
    assert!(error.components.is_some());
}

#[test]
fn pending_fingerprints_never_expose_payload_or_digest_in_debug() {
    let request = PendingInput::Write(b"private write").snapshot(13).unwrap();
    let debug = format!("{request:?}");
    assert!(!debug.contains("private"));
    assert!(!debug.contains("digest"));
    assert!(request.valid_for(IoOperation::Write));
}
