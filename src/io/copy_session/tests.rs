use super::*;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

#[derive(Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct Reader { bytes: Vec<u8>, pos: usize, polls: usize, hold_eof: bool }
impl Reader {
    fn new(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec(), pos: 0, polls: 0, hold_eof: false }
    }
}
impl AsyncRead for Reader {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.hold_eof && this.pos == this.bytes.len() { return Poll::Pending; }
        let n = buf.remaining().min(this.bytes.len() - this.pos);
        buf.put_slice(&this.bytes[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy)]
enum Fault { Pending, Error, Zero, Panic, Overreport }
struct Writer {
    bytes: Vec<u8>, limit: usize, fault: Fault, polls: usize, blocked: usize,
    flushes: usize, flush_pending: bool, flush_error: bool, shutdowns: usize,
}
impl Writer {
    fn new(limit: usize, fault: Fault) -> Self {
        Self { bytes: Vec::new(), limit, fault, polls: 0, blocked: 0,
            flushes: 0, flush_pending: false, flush_error: false, shutdowns: 0 }
    }
}
impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.bytes.len() >= this.limit {
            this.blocked += 1;
            return match this.fault {
                Fault::Pending => Poll::Pending,
                Fault::Error => Poll::Ready(Err(io::Error::from_raw_os_error(17))),
                Fault::Zero => Poll::Ready(Ok(0)),
                Fault::Panic => panic!("copy provider panic sentinel"),
                Fault::Overreport => Poll::Ready(Ok(bytes.len() + 1)),
            };
        }
        let n = bytes.len().min(this.limit - this.bytes.len()).min(3);
        this.bytes.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.flushes += 1;
        if this.flush_pending { return Poll::Pending; }
        if std::mem::take(&mut this.flush_error) {
            return Poll::Ready(Err(io::Error::from_raw_os_error(19)));
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

fn poll_once<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut CopySession<R, W>, cx: &Cx,
) -> Poll<io::Result<u64>> {
    let mut run = std::pin::pin!(session.run(cx));
    run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn finish<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(session: &mut CopySession<R, W>, cx: &Cx) -> u64 {
    for _ in 0..1024 {
        if let Poll::Ready(result) = poll_once(session, cx) { return result.unwrap(); }
    }
    panic!("copy did not finish within the deterministic test bound");
}
fn invariant(progress: CopySessionProgress) {
    assert_eq!(progress.read - progress.written, progress.buffered as u64);
}

#[test]
fn every_partial_write_boundary_survives_future_drop_and_recoverable_failure() {
    let input: Vec<u8> = (0..31).collect();
    for capacity in [1, 2, 7, 16, 64] {
        for prefix in 0..input.len() {
            for fault in [Fault::Pending, Fault::Error, Fault::Zero] {
                let cx = Cx::for_testing();
                let mut session = CopySession::with_capacity(
                    Reader::new(&input), Writer::new(prefix, fault), capacity,
                ).unwrap();
                let mut blocked = None;
                for _ in 0..128 {
                    let result = poll_once(&mut session, &cx);
                    invariant(session.progress());
                    if session.writer.blocked != 0 { blocked = Some(result); break; }
                    assert!(result.is_pending());
                }
                match (fault, blocked.expect("actually reached the writer boundary")) {
                    (Fault::Pending, Poll::Pending) => {}
                    (Fault::Error, Poll::Ready(Err(error))) => assert_eq!(error.raw_os_error(), Some(17)),
                    (Fault::Zero, Poll::Ready(Err(error))) => assert_eq!(error.kind(), io::ErrorKind::WriteZero),
                    _ => panic!("wrong failure shape"),
                }
                let before = session.progress();
                assert_eq!(before.written, prefix as u64);
                assert!(before.buffered > 0);
                assert_eq!(session.pending_bytes(), &input[prefix..before.read as usize]);
                // Repeatedly create and drop borrowing futures at the same boundary.
                for _ in 0..3 {
                    let _ = poll_once(&mut session, &cx);
                    assert_eq!(session.progress(), before);
                }
                session.writer.limit = usize::MAX;
                assert_eq!(finish(&mut session, &cx), input.len() as u64);
                assert_eq!(session.writer.bytes, input);
                assert!(session.pending_bytes().is_empty());
                assert!(session.is_complete());
                invariant(session.progress());
                assert_eq!(session.writer.shutdowns, 0, "one-way copying only flushes");
            }
        }
    }
}

#[test]
fn cancellation_preserves_read_ahead_and_a_fresh_context_resumes_it() {
    let cx = Cx::for_testing();
    let mut session = CopySession::new(Reader::new(b"payload"), Writer::new(2, Fault::Pending));
    assert!(poll_once(&mut session, &cx).is_pending());
    let before = session.progress();
    cx.cancel_with(crate::types::CancelKind::User, Some("pause transfer"));
    let Poll::Ready(Err(error)) = poll_once(&mut session, &cx) else { panic!("cancelled run must return"); };
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(session.progress(), before);
    assert_eq!(session.pending_bytes(), b"yload");
    session.writer.limit = usize::MAX;
    assert_eq!(finish(&mut session, &Cx::for_testing()), 7);
    assert_eq!(session.writer.bytes, b"payload");
}

#[test]
fn parked_run_registers_cancellation_and_drop_retires_its_registration() {
    let cx = Cx::for_testing();
    let count = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut session = CopySession::new(Reader::new(b"payload"), Writer::new(0, Fault::Pending));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let before = count.0.load(Ordering::SeqCst);
        cx.cancel_with(crate::types::CancelKind::User, Some("wake parked copy"));
        assert!(count.0.load(Ordering::SeqCst) > before);
        assert!(matches!(run.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
    }
    let fresh = Cx::for_testing();
    {
        let mut run = std::pin::pin!(session.run(&fresh));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    let before = count.0.load(Ordering::SeqCst);
    fresh.cancel_with(crate::types::CancelKind::User, Some("dropped wait"));
    assert_eq!(count.0.load(Ordering::SeqCst), before, "no stale session cancel waiter");
}

#[test]
fn final_flush_can_pause_and_fail_without_rewriting_data() {
    let cx = Cx::for_testing();
    let mut writer = Writer::new(usize::MAX, Fault::Pending);
    writer.flush_pending = true;
    let mut session = CopySession::new(Reader::new(b"data"), writer);
    assert!(poll_once(&mut session, &cx).is_pending());
    assert!(session.progress().read_eof);
    assert!(!session.is_complete());
    assert_eq!(session.progress().written, 4);
    let writes = session.writer.polls;
    session.writer.flush_pending = false;
    session.writer.flush_error = true;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.raw_os_error() == Some(19)));
    assert_eq!(finish(&mut session, &cx), 4);
    assert_eq!(session.writer.polls, writes);
    assert_eq!(session.writer.bytes, b"data");
}

#[test]
fn temporary_source_pending_flushes_committed_output_without_fabricating_eof() {
    let cx = Cx::for_testing();
    let mut reader = Reader::new(b"request");
    reader.hold_eof = true;
    let mut session = CopySession::new(reader, Writer::new(usize::MAX, Fault::Pending));
    assert!(poll_once(&mut session, &cx).is_pending());
    assert_eq!(session.writer.bytes, b"request");
    assert!(session.progress().flushed);
    assert!(!session.progress().read_eof);
    let flushes = session.writer.flushes;
    assert!(poll_once(&mut session, &cx).is_pending());
    assert_eq!(session.writer.flushes, flushes);
    session.reader.hold_eof = false;
    assert_eq!(finish(&mut session, &cx), 7);
}

#[test]
fn extraction_returns_the_advanced_reader_and_the_unwritten_suffix() {
    let cx = Cx::for_testing();
    let mut session = CopySession::with_capacity(Reader::new(b"abcdefgh"), Writer::new(3, Fault::Pending), 5).unwrap();
    assert!(poll_once(&mut session, &cx).is_pending());
    let (reader, writer, pending) = session.into_parts();
    assert_eq!(reader.pos, 5);
    assert_eq!(writer.bytes, b"abc");
    assert_eq!(pending, b"de");
    let reconstructed: Vec<_> = writer.bytes.iter().chain(&pending).chain(&reader.bytes[reader.pos..]).copied().collect();
    assert_eq!(reconstructed, b"abcdefgh");
}

#[test]
fn impossible_write_progress_is_sticky_and_never_retries_the_provider() {
    let cx = Cx::for_testing();
    let mut session = CopySession::new(Reader::new(b"data"), Writer::new(0, Fault::Overreport));
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    let before = session.progress();
    let polls = session.writer.polls;
    session.writer.limit = usize::MAX;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.writer.polls, polls);
    assert_eq!(session.progress(), before);
    assert!(!session.is_complete());
}

#[test]
fn provider_panic_propagates_and_poison_prevents_ambiguous_retries() {
    let cx = Cx::for_testing();
    let mut session = CopySession::new(Reader::new(b"data"), Writer::new(0, Fault::Panic));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(&mut session, &cx))).unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"copy provider panic sentinel"));
    let polls = session.writer.polls;
    session.writer.limit = usize::MAX;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.writer.polls, polls);
    assert_eq!(session.pending_bytes(), b"data");
}

#[test]
fn completed_runs_are_idempotent_and_debug_does_not_disclose_payloads() {
    let cx = Cx::for_testing();
    let mut session = CopySession::new(Reader::new(b"secret-payload"), Writer::new(usize::MAX, Fault::Pending));
    assert_eq!(finish(&mut session, &cx), 14);
    let before = (session.reader.polls, session.writer.polls, session.writer.flushes);
    cx.cancel_with(crate::types::CancelKind::User, Some("after completion"));
    assert_eq!(finish(&mut session, &cx), 14);
    assert_eq!((session.reader.polls, session.writer.polls, session.writer.flushes), before);
    assert!(!format!("{session:?}").contains("secret-payload"));
}

#[test]
fn zero_capacity_and_zero_input_do_not_fabricate_reads_or_skip_flush() {
    assert!(matches!(CopySession::with_capacity(Reader::new(b""), Writer::new(usize::MAX, Fault::Pending), 0),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    let mut session = CopySession::new(Reader::new(b""), Writer::new(usize::MAX, Fault::Pending));
    assert_eq!(finish(&mut session, &Cx::for_testing()), 0);
    assert_eq!(session.writer.polls, 0);
    assert_eq!(session.writer.flushes, 1);
    assert!(session.is_complete());
}

#[test]
fn cooperative_quantum_yields_and_counter_exhaustion_never_becomes_eof() {
    let cx = Cx::for_testing();
    let count = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut session = CopySession::with_capacity(Reader::new(&[1; 256]), Writer::new(usize::MAX, Fault::Pending), 1).unwrap();
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(session.reader.polls + session.writer.polls, POLL_BUDGET);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(finish(&mut session, &cx), 256);

    let mut session = CopySession::new(Reader::new(b"x"), Writer::new(usize::MAX, Fault::Pending));
    session.direction.read = u64::MAX;
    session.direction.written = u64::MAX;
    assert!(matches!(poll_once(&mut session, &Cx::for_testing()), Poll::Ready(Err(_))));
    assert_eq!(session.reader.polls, 0);
    assert!(!session.progress().read_eof);
    invariant(session.progress());
}
