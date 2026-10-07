use super::*;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

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
    Eof,
    Panic,
}

struct Reader {
    bytes: Vec<u8>,
    pos: usize,
    limit: usize,
    chunk: usize,
    polls: usize,
    stop: Stop,
}

impl Reader {
    fn new(bytes: &[u8], limit: usize, stop: Stop) -> Self {
        Self { bytes: bytes.to_vec(), pos: 0, limit, chunk: 3, polls: 0, stop }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.pos >= this.limit {
            return match this.stop {
                Stop::Pending => Poll::Pending,
                Stop::Error => Poll::Ready(Err(io::Error::from_raw_os_error(17))),
                Stop::Eof => Poll::Ready(Ok(())),
                Stop::Panic => panic!("exact read panic sentinel"),
            };
        }
        let n = buffer.remaining()
            .min(this.bytes.len() - this.pos)
            .min(this.limit - this.pos)
            .min(this.chunk);
        buffer.put_slice(&this.bytes[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

fn poll_once<R: AsyncRead + Unpin>(
    session: &mut ReadExactSession<'_, R>,
    cx: &Cx,
) -> Poll<io::Result<usize>> {
    let mut run = std::pin::pin!(session.run(cx));
    run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

fn finish<R: AsyncRead + Unpin>(session: &mut ReadExactSession<'_, R>, cx: &Cx) -> usize {
    for _ in 0..128 {
        if let Poll::Ready(result) = poll_once(session, cx) {
            return result.unwrap();
        }
    }
    panic!("exact read exceeded deterministic poll bound");
}

#[test]
fn every_partial_boundary_survives_drop_error_and_eof_without_replacing_the_prefix() {
    let input: Vec<u8> = (0..67).collect();
    for prefix in 0..input.len() {
        for stop in [Stop::Pending, Stop::Error, Stop::Eof] {
            let cx = Cx::for_testing();
            let mut destination = vec![255; input.len()];
            let mut session = ReadExactSession::new(
                Reader::new(&input, prefix, stop), &mut destination,
            );
            let result = poll_once(&mut session, &cx);
            match stop {
                Stop::Pending => assert!(result.is_pending()),
                Stop::Error => assert!(matches!(result, Poll::Ready(Err(error)) if error.raw_os_error() == Some(17))),
                Stop::Eof => assert!(matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof)),
                Stop::Panic => unreachable!(),
            }
            assert_eq!(session.bytes_read(), prefix);
            assert_eq!(session.filled(), &input[..prefix]);
            assert_eq!(session.remaining(), input.len() - prefix);
            session.reader.limit = usize::MAX;
            assert_eq!(finish(&mut session, &cx), input.len());
            assert_eq!(session.filled(), input);
            assert!(session.is_complete());
            assert_eq!(session.reader.pos, input.len());
        }
    }
}

#[test]
fn cancelled_context_does_not_consume_and_a_live_context_resumes() {
    let cx = Cx::for_testing();
    let mut bytes = [0; 7];
    let mut session = ReadExactSession::new(Reader::new(b"payload", 2, Stop::Pending), &mut bytes);
    assert!(poll_once(&mut session, &cx).is_pending());
    cx.cancel_with(crate::types::CancelKind::User, Some("pause exact read"));
    let polls = session.reader.polls;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
    assert_eq!(session.reader.polls, polls);
    assert_eq!(session.filled(), b"pa");
    session.reader.limit = usize::MAX;
    assert_eq!(finish(&mut session, &Cx::for_testing()), 7);
    assert_eq!(session.filled(), b"payload");
}

#[test]
fn idle_cancellation_wakes_the_current_waiter_and_drop_retires_it() {
    let cx = Cx::for_testing();
    let old = Arc::new(WakeCount::default());
    let current = Arc::new(WakeCount::default());
    let old_waker = Waker::from(Arc::clone(&old));
    let current_waker = Waker::from(Arc::clone(&current));
    let mut bytes = [0; 1];
    let mut session = ReadExactSession::new(Reader::new(b"x", 0, Stop::Pending), &mut bytes);
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
        assert!(run.as_mut().poll(&mut Context::from_waker(&current_waker)).is_pending());
        cx.cancel_with(crate::types::CancelKind::User, Some("wake exact read"));
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert!(current.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(run.as_mut().poll(&mut Context::from_waker(&current_waker)),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
    }
    let fresh = Cx::for_testing();
    {
        let mut run = std::pin::pin!(session.run(&fresh));
        assert!(run.as_mut().poll(&mut Context::from_waker(&current_waker)).is_pending());
    }
    let before = current.0.load(Ordering::SeqCst);
    fresh.cancel_with(crate::types::CancelKind::User, Some("after drop"));
    assert_eq!(current.0.load(Ordering::SeqCst), before);
}

#[test]
fn completed_and_empty_sessions_do_not_poll_a_provider_or_check_cancellation() {
    let cx = Cx::for_testing();
    let mut destination = [0; 4];
    let mut session = ReadExactSession::new(Reader::new(b"dataextra", 9, Stop::Panic), &mut destination);
    assert_eq!(finish(&mut session, &cx), 4);
    let polls = session.reader.polls;
    cx.cancel_with(crate::types::CancelKind::User, Some("done"));
    assert_eq!(finish(&mut session, &cx), 4);
    assert_eq!(session.reader.polls, polls);
    assert_eq!(session.reader.pos, 4, "must not read past the frame boundary");
    let mut empty = [];
    let mut session = ReadExactSession::new(Reader::new(b"", 0, Stop::Panic), &mut empty);
    assert_eq!(finish(&mut session, &cx), 0);
    assert_eq!(session.reader.polls, 0);
}

#[test]
fn panic_propagates_and_poison_refuses_unknown_reader_effects() {
    let cx = Cx::for_testing();
    let mut destination = [0; 7];
    let mut session = ReadExactSession::new(Reader::new(b"payload", 2, Stop::Panic), &mut destination);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(&mut session, &cx))).unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"exact read panic sentinel"));
    assert!(session.is_poisoned());
    assert!(!session.is_complete());
    assert_eq!(session.filled(), b"pa");
    session.reader.limit = usize::MAX;
    let polls = session.reader.polls;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.reader.polls, polls);
}

#[test]
fn cooperative_quantum_preserves_progress_and_wakes_before_yielding() {
    let cx = Cx::for_testing();
    let mut destination = [0; POLL_BUDGET + 1];
    let mut reader = Reader::new(&[42; POLL_BUDGET + 1], usize::MAX, Stop::Panic);
    reader.chunk = 1;
    let mut session = ReadExactSession::new(reader, &mut destination);
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(session.bytes_read(), POLL_BUDGET);
    assert_eq!(session.reader.polls, POLL_BUDGET);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(finish(&mut session, &cx), POLL_BUDGET + 1);
}

#[test]
fn extraction_keeps_the_advanced_reader_buffer_and_offset_together() {
    let cx = Cx::for_testing();
    let mut destination = [0; 7];
    let mut session = ReadExactSession::new(Reader::new(b"payload", 2, Stop::Pending), &mut destination);
    assert!(poll_once(&mut session, &cx).is_pending());
    assert!(!format!("{session:?}").contains("payload"));
    let (reader, buffer, offset) = session.into_parts();
    assert_eq!(reader.pos, offset);
    assert_eq!(offset, 2);
    assert_eq!(&buffer[..offset], b"pa");
}

struct ReportThenStop {
    error: bool,
}

impl AsyncRead for ReportThenStop {
    fn poll_read(
        self: Pin<&mut Self>, _: &mut Context<'_>, buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        buffer.put_slice(b"x");
        if self.error {
            Poll::Ready(Err(io::Error::from_raw_os_error(19)))
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn progress_reported_with_pending_or_error_is_never_forgotten() {
    let cx = Cx::for_testing();
    for error in [false, true] {
        let mut destination = [0; 2];
        let mut session = ReadExactSession::new(ReportThenStop { error }, &mut destination);
        if error {
            assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.raw_os_error() == Some(19)));
            assert_eq!(session.filled(), b"x");
        } else {
            assert_eq!(finish(&mut session, &cx), 2);
            assert_eq!(session.filled(), b"xx");
        }
    }
}
