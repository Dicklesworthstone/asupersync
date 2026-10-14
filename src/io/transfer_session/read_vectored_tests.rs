use super::*;
use crate::io::{AsyncRead, ReadBuf};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[derive(Clone, Copy)]
enum Stop { Pending, Error, Eof, Interrupted, Overreport, ReplaceReady, ReplacePending, Panic }
struct Reader {
    source: &'static [u8],
    pos: usize,
    limit: usize,
    chunk: usize,
    calls: usize,
    widest: usize,
    stop: Stop,
}
impl Reader {
    fn new(limit: usize, stop: Stop) -> Self {
        Self { source: b"HEADpayloadTRAILextra", pos: 0, limit, chunk: 4, calls: 0, widest: 0, stop }
    }
}
impl AsyncRead for Reader {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        panic!("scatter-capable reader must receive vectored requests");
    }
}
impl AsyncReadVectored for Reader {
    fn poll_read_vectored(
        self: Pin<&mut Self>, _: &mut Context<'_>, buffers: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.calls += 1;
        this.widest = this.widest.max(buffers.len());
        assert!(!buffers.is_empty());
        assert!(buffers.len() <= MAX_SLICES);
        assert!(buffers.iter().all(|buffer| !buffer.is_empty()));
        let offered: usize = buffers.iter().map(|buffer| buffer.len()).sum();
        if this.pos >= this.limit {
            return match this.stop {
                Stop::Pending => Poll::Pending,
                Stop::Error => Poll::Ready(Err(io::Error::from_raw_os_error(17))),
                Stop::Eof => Poll::Ready(Ok(0)),
                Stop::Interrupted => Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "scatter reader interrupted"))),
                Stop::Overreport => Poll::Ready(Ok(offered + 1)),
                Stop::ReplaceReady | Stop::ReplacePending => {
                    buffers[0] = IoSliceMut::new(&mut []);
                    match this.stop {
                        Stop::ReplacePending => Poll::Pending,
                        _ => Poll::Ready(Ok(1)),
                    }
                }
                Stop::Panic => {
                    buffers[0][0] = 255;
                    this.pos += 1;
                    panic!("scatter read panic sentinel");
                }
            };
        }
        let n = offered.min(this.limit - this.pos).min(this.chunk).min(this.source.len() - this.pos);
        let mut left = n;
        for buffer in buffers {
            let count = buffer.len().min(left);
            buffer[..count].copy_from_slice(&this.source[this.pos..this.pos + count]);
            this.pos += count;
            left -= count;
        }
        Poll::Ready(Ok(n))
    }
}

fn poll_once<R: AsyncReadVectored + Unpin>(
    session: &mut ReadExactVectoredSession<'_, '_, R>,
    cx: &Cx,
) -> Poll<io::Result<usize>> {
    let mut run = std::pin::pin!(session.run(cx));
    run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn finish<R: AsyncReadVectored + Unpin>(
    session: &mut ReadExactVectoredSession<'_, '_, R>,
    cx: &Cx,
) -> usize {
    for _ in 0..128 {
        if let Poll::Ready(result) = poll_once(session, cx) { return result.unwrap(); }
    }
    panic!("scatter read exceeded deterministic poll bound");
}
fn filled<R>(session: &ReadExactVectoredSession<'_, '_, R>) -> Vec<u8> {
    session.filled_slices().flat_map(|slice| slice.iter().copied()).collect()
}

#[test]
fn every_partial_boundary_survives_drop_error_and_eof_without_reconsumption() {
    let expected = b"HEADpayloadTRAIL";
    for prefix in 0..expected.len() {
        for stop in [Stop::Pending, Stop::Error, Stop::Eof] {
            let mut a = [0xa5; 3];
            let mut b = [0xa5; 5];
            let mut c = [0xa5; 8];
            let mut buffers = [IoSliceMut::new(&mut []), IoSliceMut::new(&mut a), IoSliceMut::new(&mut []), IoSliceMut::new(&mut b), IoSliceMut::new(&mut c)];
            let mut session = ReadExactVectoredSession::new(Reader::new(prefix, stop), &mut buffers).unwrap();
            let cx = Cx::for_testing();
            let result = poll_once(&mut session, &cx);
            match stop {
                Stop::Pending => assert!(result.is_pending()),
                Stop::Error => assert!(matches!(result, Poll::Ready(Err(e)) if e.raw_os_error() == Some(17))),
                Stop::Eof => assert!(matches!(result, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof)),
                _ => unreachable!(),
            }
            assert_eq!(session.bytes_read(), prefix);
            assert_eq!(session.remaining(), expected.len() - prefix);
            assert_eq!(session.reader.pos, prefix);
            assert_eq!(filled(&session), expected[..prefix]);
            for _ in 0..3 {
                let _ = poll_once(&mut session, &cx);
                assert_eq!(session.bytes_read(), prefix);
                assert_eq!(session.reader.pos, prefix);
                assert_eq!(filled(&session), expected[..prefix]);
            }
            session.reader.limit = usize::MAX;
            assert_eq!(finish(&mut session, &cx), expected.len());
            assert_eq!(filled(&session), expected);
            assert_eq!(session.reader.pos, expected.len());
            assert!(session.reader.widest >= 2);
            assert!(session.is_complete());
        }
    }
}

#[test]
fn scalar_fallback_preserves_unread_source_and_fills_each_destination() {
    let mut a = [0; 4];
    let mut b = [0; 7];
    let mut buffers = [IoSliceMut::new(&mut []), IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
    let mut session = ReadExactVectoredSession::new(&b"HEADpayloadextra"[..], &mut buffers).unwrap();
    assert_eq!(finish(&mut session, &Cx::for_testing()), 11);
    assert_eq!(filled(&session), b"HEADpayload");
    let (source, buffers, read) = session.into_parts();
    assert_eq!(source, b"extra");
    assert_eq!(read, 11);
    assert_eq!(&*buffers[1], b"HEAD");
    assert_eq!(&*buffers[2], b"payload");
}

#[test]
fn parked_cancellation_wakes_without_an_io_event_and_dropped_runs_unregister() {
    let mut a = [0; 4];
    let mut b = [0; 12];
    let mut buffers = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
    let mut session = ReadExactVectoredSession::new(Reader::new(5, Stop::Pending), &mut buffers).unwrap();
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let before = count.0.load(Ordering::SeqCst);
        cx.cancel_with(crate::types::CancelKind::User, Some("pause scatter read"));
        assert!(count.0.load(Ordering::SeqCst) > before);
        assert!(matches!(run.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted));
    }
    assert_eq!(filled(&session), b"HEADp");
    assert_eq!(session.bytes_read(), 5);
    let calls = session.reader.calls;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted));
    assert_eq!(session.reader.calls, calls);
    let fresh = Cx::for_testing();
    {
        let mut run = std::pin::pin!(session.run(&fresh));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    let before = count.0.load(Ordering::SeqCst);
    fresh.cancel_with(crate::types::CancelKind::User, Some("after dropped read"));
    assert_eq!(count.0.load(Ordering::SeqCst), before);
    session.reader.limit = usize::MAX;
    assert_eq!(finish(&mut session, &Cx::for_testing()), 16);
    assert_eq!(filled(&session), b"HEADpayloadTRAIL");
}

#[test]
fn descriptor_mutation_is_sticky_even_on_pending_and_does_not_replace_the_caller_plan() {
    for stop in [Stop::ReplacePending, Stop::ReplaceReady] {
        let mut a = [0xa5; 4];
        let mut b = [0xa5; 7];
        let mut buffers = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
        let identities: Vec<_> = buffers.iter().map(|b| (b.as_ptr(), b.len())).collect();
        let mut session = ReadExactVectoredSession::new(Reader::new(0, stop), &mut buffers).unwrap();
        let cx = Cx::for_testing();
        assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
        assert!(session.is_poisoned());
        assert_eq!(session.bytes_read(), 0);
        session.reader.limit = usize::MAX;
        assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
        assert_eq!(session.reader.calls, 1);
        let (_, buffers, read) = session.into_parts();
        assert_eq!(read, 0);
        assert_eq!(identities, buffers.iter().map(|b| (b.as_ptr(), b.len())).collect::<Vec<_>>());
        assert!(buffers.iter().flat_map(|b| b.iter()).all(|&b| b == 0xa5));
    }
}

#[test]
fn impossible_count_is_rejected_against_the_current_window_without_cursor_advance() {
    let mut storage = [[0; 1]; MAX_SLICES * 2];
    let mut buffers: Vec<_> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut session = ReadExactVectoredSession::new(Reader::new(0, Stop::Overreport), &mut buffers).unwrap();
    let cx = Cx::for_testing();
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
    assert!(session.is_poisoned());
    assert_eq!(session.bytes_read(), 0);
    session.reader.limit = usize::MAX;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.reader.calls, 1);
}

#[test]
fn provider_panic_preserves_the_original_payload_and_prohibits_replay() {
    let mut a = [0; 4];
    let mut b = [0; 12];
    let mut buffers = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
    let mut session = ReadExactVectoredSession::new(Reader::new(5, Stop::Panic), &mut buffers).unwrap();
    let cx = Cx::for_testing();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(&mut session, &cx))).unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"scatter read panic sentinel"));
    assert!(session.is_poisoned());
    assert_eq!(session.bytes_read(), 5);
    assert_eq!(filled(&session), b"HEADp");
    let calls = session.reader.calls;
    session.reader.limit = usize::MAX;
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData));
    assert_eq!(session.reader.calls, calls);
}

#[test]
fn provider_interruption_is_returned_once_and_a_retry_keeps_the_same_buffers() {
    let mut a = [0; 4];
    let mut buffers = [IoSliceMut::new(&mut a)];
    let mut session = ReadExactVectoredSession::new(Reader::new(0, Stop::Interrupted), &mut buffers).unwrap();
    let cx = Cx::for_testing();
    assert!(matches!(poll_once(&mut session, &cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted && e.to_string() == "scatter reader interrupted"));
    assert!(!cx.is_cancel_requested());
    assert_eq!(session.reader.calls, 1);
    session.reader.limit = usize::MAX;
    assert_eq!(finish(&mut session, &cx), 4);
    assert_eq!(filled(&session), b"HEAD");
}

#[test]
fn empty_and_complete_destinations_do_not_poll_or_consume_extra_input() {
    let cx = Cx::for_testing();
    cx.cancel_with(crate::types::CancelKind::User, Some("cancelled before empty read"));
    let mut buffers = [IoSliceMut::new(&mut [])];
    let mut session = ReadExactVectoredSession::new(Reader::new(0, Stop::Panic), &mut buffers).unwrap();
    assert_eq!(finish(&mut session, &cx), 0);
    assert_eq!(session.reader.calls, 0);
    let mut a = [0; 4];
    let mut buffers = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut [])];
    let mut session = ReadExactVectoredSession::new(Reader::new(usize::MAX, Stop::Panic), &mut buffers).unwrap();
    assert_eq!(finish(&mut session, &Cx::for_testing()), 4);
    let calls = session.reader.calls;
    assert_eq!(finish(&mut session, &cx), 4);
    assert_eq!(session.reader.pos, 4);
    assert_eq!(session.reader.calls, calls);
}

#[test]
fn descriptor_and_poll_work_is_bounded_even_with_empty_destinations() {
    let mut storage = [[0; 1]; MAX_SLICES * 2 + 1];
    let mut buffers: Vec<_> = (0..MAX_SLICES * POLL_BUDGET + 1).map(|_| IoSliceMut::new(&mut [])).collect();
    buffers.extend(storage.iter_mut().map(|b| IoSliceMut::new(b)));
    let mut reader = Reader::new(usize::MAX, Stop::Panic);
    reader.source = b"0123456789012345678901234567890123456789";
    reader.chunk = usize::MAX;
    let mut session = ReadExactVectoredSession::new(reader, &mut buffers).unwrap();
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    {
        let mut run = std::pin::pin!(session.run(&cx));
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(session.slice, MAX_SLICES * POLL_BUDGET);
    assert_eq!(session.reader.calls, 0);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(finish(&mut session, &cx), MAX_SLICES * 2 + 1);
    assert_eq!(session.reader.widest, MAX_SLICES);
    assert_eq!(session.reader.calls, 3);
    assert_eq!(filled(&session), &session.reader.source[..MAX_SLICES * 2 + 1]);
}

#[test]
fn extraction_preserves_reported_prefix_and_untouched_destination_suffix() {
    let mut a = [0xa5; 4];
    let mut b = [0xa5; 12];
    let mut buffers = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
    let mut session = ReadExactVectoredSession::new(Reader::new(5, Stop::Pending), &mut buffers).unwrap();
    assert!(poll_once(&mut session, &Cx::for_testing()).is_pending());
    assert!(!format!("{session:?}").contains("HEAD"));
    let (reader, buffers, read) = session.into_parts();
    assert_eq!(reader.pos, 5);
    assert_eq!(read, 5);
    let contents: Vec<_> = buffers.iter().flat_map(|b| b.iter().copied()).collect();
    assert_eq!(&contents[..read], b"HEADp");
    assert_eq!(&contents[read..], &[0xa5; 11]);
}

#[test]
fn a_heap_allocated_destination_plan_can_be_reused_after_its_session_ends() {
    let mut storage = [[0; 2]; 2];
    let mut buffers: Vec<_> = storage.iter_mut().map(|part| IoSliceMut::new(part)).collect();
    let cx = Cx::for_testing();
    {
        let mut session = ReadExactVectoredSession::new(&b"ABCD"[..], &mut buffers).unwrap();
        assert_eq!(finish(&mut session, &cx), 4);
    }
    assert_eq!(&*buffers[0], b"AB");
    assert_eq!(&*buffers[1], b"CD");
    {
        let mut session = ReadExactVectoredSession::new(&b"EFGH"[..], &mut buffers).unwrap();
        assert_eq!(finish(&mut session, &cx), 4);
    }
    drop(buffers);
    assert_eq!(storage, [*b"EF", *b"GH"]);
}
