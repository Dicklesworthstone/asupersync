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
    calls: usize,
    widest: usize,
    stop: Stop,
}
impl Writer {
    fn new(limit: usize, stop: Stop) -> Self {
        Self { bytes: Vec::new(), limit, chunk: 4, calls: 0, widest: 0, stop }
    }
}
impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        panic!("vectored-capable writer must receive scatter/gather requests");
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.calls += 1;
        this.widest = this.widest.max(buffers.len());
        assert!(!buffers.is_empty());
        assert!(buffers.len() <= MAX_SLICES);
        assert!(buffers.iter().all(|buffer| !buffer.is_empty()));
        let offered: usize = buffers.iter().map(|buffer| buffer.len()).sum();
        if this.bytes.len() >= this.limit {
            return match this.stop {
                Stop::Pending => Poll::Pending,
                Stop::Error => Poll::Ready(Err(io::Error::from_raw_os_error(17))),
                Stop::Interrupted => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted, "vectored provider interrupted",
                ))),
                Stop::Zero => Poll::Ready(Ok(0)),
                Stop::Overreport => Poll::Ready(Ok(offered + 1)),
                Stop::Panic => {
                    this.bytes.push(255);
                    panic!("vectored provider panic sentinel");
                }
            };
        }
        let accepted = offered.min(this.limit - this.bytes.len()).min(this.chunk);
        let mut left = accepted;
        for buffer in buffers {
            let n = buffer.len().min(left);
            this.bytes.extend_from_slice(&buffer[..n]);
            left -= n;
        }
        Poll::Ready(Ok(accepted))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("write-all must not flush");
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("write-all must not shut down");
    }
}

fn poll_once<W: AsyncWrite + Unpin>(
    session: &mut WriteAllVectoredSession<'_, W>, cx: &Cx,
) -> Poll<io::Result<usize>> {
    let mut run = std::pin::pin!(session.run(cx));
    run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn finish<W: AsyncWrite + Unpin>(session: &mut WriteAllVectoredSession<'_, W>, cx: &Cx) -> usize {
    for _ in 0..128 {
        if let Poll::Ready(result) = poll_once(session, cx) {
            return result.unwrap();
        }
    }
    panic!("vectored session exceeded deterministic poll bound");
}

#[test]
fn every_prefix_across_slice_boundaries_survives_drop_error_and_write_zero() {
    let input = b"HEADpayloadTRAIL";
    let buffers = [
        IoSlice::new(b""), IoSlice::new(b"HEAD"), IoSlice::new(b""),
        IoSlice::new(b"payload"), IoSlice::new(b"TRAIL"), IoSlice::new(b""),
    ];
    let pointers: Vec<_> = buffers.iter().map(|buffer| (buffer.as_ptr(), buffer.len())).collect();
    for prefix in 0..input.len() {
        for stop in [Stop::Pending, Stop::Error, Stop::Zero] {
            let cx = Cx::for_testing();
            let mut session = WriteAllVectoredSession::new(Writer::new(prefix, stop), &buffers).unwrap();
            let result = poll_once(&mut session, &cx);
            match stop {
                Stop::Pending => assert!(result.is_pending()),
                Stop::Error => assert!(matches!(result, Poll::Ready(Err(e)) if e.raw_os_error() == Some(17))),
                Stop::Zero => assert!(matches!(result, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::WriteZero)),
                _ => unreachable!(),
            }
            assert_eq!(session.bytes_written(), prefix);
            assert_eq!(session.remaining(), input.len() - prefix);
            assert_eq!(session.writer.bytes, input[..prefix]);
            for _ in 0..3 {
                let _ = poll_once(&mut session, &cx);
                assert_eq!(session.bytes_written(), prefix);
                assert_eq!(session.writer.bytes, input[..prefix]);
            }
            session.writer.limit = usize::MAX;
            assert_eq!(finish(&mut session, &cx), input.len());
            assert_eq!(session.writer.bytes, input);
            assert!(session.is_complete());
            assert!(session.writer.widest >= 2);
        }
    }
    assert_eq!(pointers, buffers.iter().map(|buffer| (buffer.as_ptr(), buffer.len())).collect::<Vec<_>>());
}

#[test]
fn scalar_fallback_writes_all_slices_without_a_vectored_override() {
    let buffers = [IoSlice::new(b""), IoSlice::new(b"head"), IoSlice::new(b"body")];
    let mut output = std::io::Cursor::new(Vec::new());
    assert!(!AsyncWrite::is_write_vectored(&output));
    let mut session = WriteAllVectoredSession::new(&mut output, &buffers).unwrap();
    assert_eq!(finish(&mut session, &Cx::for_testing()), 8);
    drop(session);
    assert_eq!(output.into_inner(), b"headbody");
}

#[test]
fn parked_cancellation_wakes_preserves_progress_and_drop_unregisters() {
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let buffers = [IoSlice::new(b"head"), IoSlice::new(b"body")];
    let mut session = WriteAllVectoredSession::new(Writer::new(5, Stop::Pending), &buffers).unwrap();
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let before = count.0.load(Ordering::SeqCst);
        cx.cancel_with(crate::types::CancelKind::User, Some("pause vectored write"));
        assert!(count.0.load(Ordering::SeqCst) > before);
        assert!(matches!(run.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
    }
    assert_eq!(session.writer.bytes, b"headb");
    assert_eq!(session.bytes_written(), 5);
    let calls = session.writer.calls;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
    assert_eq!(session.writer.calls, calls);
    let fresh = Cx::for_testing();
    {
        let mut run = std::pin::pin!(session.run(&fresh));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    let before = count.0.load(Ordering::SeqCst);
    fresh.cancel_with(crate::types::CancelKind::User, Some("after drop"));
    assert_eq!(count.0.load(Ordering::SeqCst), before);
    session.writer.limit = usize::MAX;
    assert_eq!(finish(&mut session, &Cx::for_testing()), 8);
    assert_eq!(session.writer.bytes, b"headbody");
}

#[test]
fn provider_interruption_is_returned_without_an_automatic_retry() {
    let buffers = [IoSlice::new(b"header"), IoSlice::new(b"payload")];
    let mut session = WriteAllVectoredSession::new(Writer::new(0, Stop::Interrupted), &buffers).unwrap();
    let cx = Cx::for_testing();
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(error))
        if error.kind() == io::ErrorKind::Interrupted && error.to_string() == "vectored provider interrupted"));
    assert!(!cx.is_cancel_requested());
    assert_eq!(session.writer.calls, 1);
    assert_eq!(session.bytes_written(), 0);
    session.writer.limit = usize::MAX;
    assert_eq!(finish(&mut session, &cx), 13);
    assert_eq!(session.writer.bytes, b"headerpayload");
}

#[test]
fn impossible_count_is_checked_against_the_offered_window_not_the_total() {
    let buffers: Vec<_> = (0..MAX_SLICES * 2).map(|_| IoSlice::new(b"x")).collect();
    let mut session = WriteAllVectoredSession::new(Writer::new(0, Stop::Overreport), &buffers).unwrap();
    let cx = Cx::for_testing();
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
    assert!(session.is_poisoned());
    assert_eq!(session.bytes_written(), 0);
    assert_eq!(session.writer.calls, 1);
    session.writer.limit = usize::MAX;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.writer.calls, 1);
}

#[test]
fn provider_panic_preserves_payload_and_refuses_ambiguous_replay() {
    let buffers = [IoSlice::new(b"head"), IoSlice::new(b"body")];
    let mut session = WriteAllVectoredSession::new(Writer::new(5, Stop::Panic), &buffers).unwrap();
    let cx = Cx::for_testing();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(&mut session, &cx))).unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"vectored provider panic sentinel"));
    assert!(session.is_poisoned());
    assert!(!session.is_complete());
    assert_eq!(session.bytes_written(), 5);
    assert_eq!(session.writer.bytes, &[b'h', b'e', b'a', b'd', b'b', 255]);
    let calls = session.writer.calls;
    session.writer.limit = usize::MAX;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.writer.calls, calls);
}

#[test]
fn empty_and_completed_runs_do_no_io_even_after_cancellation() {
    let cx = Cx::for_testing();
    cx.cancel_with(crate::types::CancelKind::User, Some("already cancelled"));
    for buffers in [&[][..], &[IoSlice::new(b""), IoSlice::new(b"")][..]] {
        let mut session = WriteAllVectoredSession::new(Writer::new(0, Stop::Panic), buffers).unwrap();
        assert_eq!(finish(&mut session, &cx), 0);
        assert_eq!(session.writer.calls, 0);
    }
    let buffers = [IoSlice::new(b"head"), IoSlice::new(b"body"), IoSlice::new(b"")];
    let mut session = WriteAllVectoredSession::new(Writer::new(usize::MAX, Stop::Panic), &buffers).unwrap();
    assert_eq!(finish(&mut session, &Cx::for_testing()), 8);
    let calls = session.writer.calls;
    assert_eq!(finish(&mut session, &cx), 8);
    assert_eq!(session.writer.calls, calls);
}

#[test]
fn long_empty_runs_yield_and_large_lists_use_bounded_descriptor_windows() {
    let mut buffers: Vec<_> = (0..MAX_SLICES * POLL_BUDGET + 1).map(|_| IoSlice::new(b"")).collect();
    buffers.extend((0..MAX_SLICES * 2 + 1).map(|_| IoSlice::new(b"x")));
    let mut writer = Writer::new(usize::MAX, Stop::Panic);
    writer.chunk = usize::MAX;
    let mut session = WriteAllVectoredSession::new(writer, &buffers).unwrap();
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(session.slice, MAX_SLICES * POLL_BUDGET);
    assert_eq!(session.writer.calls, 0);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(finish(&mut session, &cx), MAX_SLICES * 2 + 1);
    assert_eq!(session.writer.bytes, vec![b'x'; MAX_SLICES * 2 + 1]);
    assert_eq!(session.writer.widest, MAX_SLICES);
    assert_eq!(session.writer.calls, 3);
}

#[test]
fn writer_poll_quantum_preserves_the_cursor_and_requests_a_wake() {
    let input = [b'x'; POLL_BUDGET + 1];
    let buffers = [IoSlice::new(&input)];
    let mut writer = Writer::new(usize::MAX, Stop::Panic);
    writer.chunk = 1;
    let mut session = WriteAllVectoredSession::new(writer, &buffers).unwrap();
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(session.bytes_written(), POLL_BUDGET);
    assert_eq!(session.writer.calls, POLL_BUDGET);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(finish(&mut session, &cx), input.len());
    assert_eq!(session.writer.bytes, input);
}

#[test]
fn extraction_returns_the_exact_suffix_and_debug_omits_payloads() {
    let buffers = [IoSlice::new(b"secret-header"), IoSlice::new(b"private-body")];
    for prefix in 0..25 {
        let mut session = WriteAllVectoredSession::new(Writer::new(prefix, Stop::Pending), &buffers).unwrap();
        assert!(poll_once(&mut session, &Cx::for_testing()).is_pending());
        let debug = format!("{session:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("private"));
        let (writer, remaining, offset) = session.into_parts();
        let suffix: Vec<_> = remaining.iter().enumerate().flat_map(|(index, buffer)| {
            let start = if index == 0 { offset } else { 0 };
            buffer[start..].iter().copied()
        }).collect();
        let mut recovered = writer.bytes;
        recovered.extend_from_slice(&suffix);
        assert_eq!(recovered, b"secret-headerprivate-body");
    }
}
