use super::*;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
enum Stop {
    Pending,
    Error,
    Interrupted,
    Zero,
    Panic,
    Overreport,
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
    chunk: usize,
    polls: usize,
    stop: Stop,
}

impl Writer {
    fn new(limit: usize, stop: Stop) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            chunk: 3,
            polls: 0,
            stop,
        }
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.bytes.len() >= this.limit {
            return match this.stop {
                Stop::Pending => Poll::Pending,
                Stop::Error => Poll::Ready(Err(io::Error::from_raw_os_error(17))),
                Stop::Interrupted => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "writer interrupted",
                ))),
                Stop::Zero => Poll::Ready(Ok(0)),
                Stop::Panic => {
                    this.bytes.push(255); // Unknown external effects before unwind.
                    panic!("exact write panic sentinel");
                }
                Stop::Overreport => Poll::Ready(Ok(usize::MAX)),
            };
        }
        let n = bytes
            .len()
            .min(this.limit - this.bytes.len())
            .min(this.chunk);
        this.bytes.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("write-all must not implicitly flush");
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("write-all must not implicitly shut down");
    }
}

fn poll_once<W: AsyncWrite + Unpin>(
    session: &mut WriteAllSession<'_, W>,
    cx: &Cx,
) -> Poll<io::Result<usize>> {
    let mut run = std::pin::pin!(session.run(cx));
    run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

fn finish<W: AsyncWrite + Unpin>(session: &mut WriteAllSession<'_, W>, cx: &Cx) -> usize {
    for _ in 0..128 {
        if let Poll::Ready(result) = poll_once(session, cx) {
            return result.unwrap();
        }
    }
    panic!("exact write exceeded deterministic poll bound");
}

#[test]
fn every_partial_write_boundary_survives_drop_error_and_zero_without_duplication() {
    let input: Vec<u8> = (0..67).collect();
    for prefix in 0..input.len() {
        for stop in [Stop::Pending, Stop::Error, Stop::Zero] {
            let cx = Cx::for_testing();
            let mut session = WriteAllSession::new(Writer::new(prefix, stop), &input);
            let result = poll_once(&mut session, &cx);
            match stop {
                Stop::Pending => assert!(result.is_pending()),
                Stop::Error => assert!(
                    matches!(result, Poll::Ready(Err(error)) if error.raw_os_error() == Some(17))
                ),
                Stop::Zero => assert!(
                    matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero)
                ),
                Stop::Interrupted | Stop::Panic | Stop::Overreport => unreachable!(),
            }
            assert_eq!(session.bytes_written(), prefix);
            assert_eq!(session.pending_bytes(), &input[prefix..]);
            assert_eq!(session.remaining(), input.len() - prefix);
            assert_eq!(session.writer.bytes, input[..prefix]);
            // Recreating disposable futures must not reset the accepted offset.
            for _ in 0..3 {
                let _ = poll_once(&mut session, &cx);
                assert_eq!(session.bytes_written(), prefix);
                assert_eq!(session.writer.bytes, input[..prefix]);
            }
            session.writer.limit = usize::MAX;
            assert_eq!(finish(&mut session, &cx), input.len());
            assert_eq!(session.writer.bytes, input);
            assert!(session.is_complete());
            assert!(session.pending_bytes().is_empty());
        }
    }
}

#[test]
fn cancellation_keeps_the_accepted_prefix_and_live_retry_only_sends_the_suffix() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(Writer::new(2, Stop::Pending), b"payload");
    assert!(poll_once(&mut session, &cx).is_pending());
    cx.cancel_with(crate::types::CancelKind::User, Some("pause exact write"));
    let polls = session.writer.polls;
    assert!(
        matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
    assert_eq!(session.writer.polls, polls);
    assert_eq!(session.writer.bytes, b"pa");
    assert_eq!(session.pending_bytes(), b"yload");
    session.writer.limit = usize::MAX;
    assert_eq!(finish(&mut session, &Cx::for_testing()), 7);
    assert_eq!(session.writer.bytes, b"payload");
}

#[test]
fn parked_writer_cancellation_wakes_and_dropped_runs_unregister() {
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut session = WriteAllSession::new(Writer::new(0, Stop::Pending), b"x");
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let before = count.0.load(Ordering::SeqCst);
        cx.cancel_with(crate::types::CancelKind::User, Some("wake exact write"));
        assert!(count.0.load(Ordering::SeqCst) > before);
        assert!(
            matches!(run.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted)
        );
    }
    let fresh = Cx::for_testing();
    {
        let mut run = std::pin::pin!(session.run(&fresh));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    let before = count.0.load(Ordering::SeqCst);
    fresh.cancel_with(crate::types::CancelKind::User, Some("after drop"));
    assert_eq!(count.0.load(Ordering::SeqCst), before);
}

#[test]
fn overreport_is_sticky_and_never_advances_or_retries_the_writer() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(Writer::new(2, Stop::Overreport), b"payload");
    assert!(
        matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert_eq!(session.bytes_written(), 2);
    assert_eq!(session.pending_bytes(), b"yload");
    assert!(session.is_poisoned());
    assert!(!session.is_complete());
    let polls = session.writer.polls;
    session.writer.limit = usize::MAX;
    assert!(
        matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert_eq!(session.writer.polls, polls);
}

#[test]
fn provider_panic_with_external_effects_propagates_and_refuses_unsafe_retry() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(Writer::new(2, Stop::Panic), b"payload");
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_once(&mut session, &cx)
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"exact write panic sentinel")
    );
    assert!(session.is_poisoned());
    assert_eq!(session.bytes_written(), 2);
    assert_eq!(session.writer.bytes, &[b'p', b'a', 255]);
    let polls = session.writer.polls;
    session.writer.limit = usize::MAX;
    assert!(
        matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert_eq!(session.writer.polls, polls);
}

#[test]
fn empty_and_completed_runs_are_idempotent_without_flush_or_shutdown() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(Writer::new(usize::MAX, Stop::Panic), b"data");
    assert_eq!(finish(&mut session, &cx), 4);
    let polls = session.writer.polls;
    cx.cancel_with(crate::types::CancelKind::User, Some("done"));
    assert_eq!(finish(&mut session, &cx), 4);
    assert_eq!(session.writer.polls, polls);
    let mut session = WriteAllSession::new(Writer::new(0, Stop::Panic), b"");
    assert_eq!(finish(&mut session, &cx), 0);
    assert_eq!(session.writer.polls, 0);
}

#[test]
fn cooperative_quantum_persists_the_offset_before_yielding() {
    let cx = Cx::for_testing();
    let input = [42; POLL_BUDGET + 1];
    let mut writer = Writer::new(usize::MAX, Stop::Panic);
    writer.chunk = 1;
    let mut session = WriteAllSession::new(writer, &input);
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    assert_eq!(session.bytes_written(), POLL_BUDGET);
    assert_eq!(session.writer.polls, POLL_BUDGET);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(finish(&mut session, &cx), input.len());
    assert_eq!(session.writer.bytes, input);
}

#[test]
fn extraction_returns_the_original_source_and_accepted_offset_without_leaking_debug_bytes() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(Writer::new(2, Stop::Pending), b"secret-payload");
    assert!(poll_once(&mut session, &cx).is_pending());
    assert!(!format!("{session:?}").contains("secret-payload"));
    let (writer, source, offset) = session.into_parts();
    assert_eq!(offset, 2);
    assert_eq!(writer.bytes, b"se");
    assert_eq!(&source[offset..], b"cret-payload");
}

#[test]
fn writer_returning_interrupted_is_distinguishable_from_cancellation_and_resumes() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(Writer::new(2, Stop::Interrupted), b"payload");
    let result = poll_once(&mut session, &cx);
    assert!(
        matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
    // Writer-produced Interrupted occurs while cx cancellation was NOT requested.
    assert!(!cx.is_cancel_requested());
    assert_eq!(session.bytes_written(), 2);
    assert_eq!(session.writer.bytes, b"pa");
    assert_eq!(session.pending_bytes(), b"yload");
    // Retry on the same session with the endpoint cleared succeeds.
    session.writer.limit = usize::MAX;
    assert_eq!(finish(&mut session, &cx), 7);
    assert_eq!(session.writer.bytes, b"payload");
    assert!(session.is_complete());
}

struct InnerCancelWriter<'a> {
    cx: &'a Cx,
    bytes: Vec<u8>,
    chunk: usize,
    polls: usize,
    cancel_on_poll: usize,
}

impl AsyncWrite for InnerCancelWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls += 1;
        let n = bytes.len().min(this.chunk);
        this.bytes.extend_from_slice(&bytes[..n]);
        if this.polls == this.cancel_on_poll {
            this.cx
                .cancel_with(crate::types::CancelKind::User, Some("inner poll cancel"));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("write-all must not implicitly flush");
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("write-all must not implicitly shut down");
    }
}

#[test]
fn cancellation_inside_inner_poll_accepting_bytes_records_progress_without_further_poll() {
    let cx = Cx::for_testing();
    let mut session = WriteAllSession::new(
        InnerCancelWriter {
            cx: &cx,
            bytes: Vec::new(),
            chunk: 3,
            polls: 0,
            cancel_on_poll: 1,
        },
        b"0123456789",
    );
    let result = poll_once(&mut session, &cx);
    assert!(
        matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
    assert!(cx.is_cancel_requested());
    // The 3 bytes accepted during the poll must be counted before the cancellation check stopped the loop.
    assert_eq!(session.bytes_written(), 3);
    assert_eq!(session.pending_bytes(), b"3456789");
    assert_eq!(session.writer.bytes, b"012");
    // No second poll must occur in the same run once cancellation is observed.
    assert_eq!(session.writer.polls, 1);

    // Resuming on a fresh live context completes the exact write.
    let fresh_cx = Cx::for_testing();
    assert_eq!(finish(&mut session, &fresh_cx), 10);
    assert_eq!(session.writer.bytes, b"0123456789");
    assert!(session.is_complete());
}
