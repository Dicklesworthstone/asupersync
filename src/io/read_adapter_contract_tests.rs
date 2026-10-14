//! Tests under `read_buf` can move its private backing slice to model an
//! invalid reader entirely in safe Rust, without leaked test allocations.

use super::ReadBuf;
use crate::io::{AsyncRead, AsyncReadVectored, Take};
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy)]
enum Status {
    Ready,
    Pending,
    Error,
}

struct Reader {
    bytes: &'static [u8],
    chunk: usize,
    status: Status,
    shifted: bool,
    panics: bool,
    polls: Arc<AtomicUsize>,
}

impl Reader {
    fn new(status: Status) -> Self {
        Self {
            bytes: b"abcdefghij",
            chunk: 3,
            status,
            shifted: false,
            panics: false,
            polls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        if this.shifted {
            let storage = std::mem::replace(buf, ReadBuf::new(&mut [])).buf;
            *buf = ReadBuf::new(&mut storage[1..]);
        }
        let n = this.bytes.len().min(this.chunk).min(buf.remaining());
        buf.put_slice(&this.bytes[..n]);
        this.bytes = &this.bytes[n..];
        assert!(!this.panics, "bounded provider panic sentinel");
        if n == 0 {
            return Poll::Ready(Ok(()));
        }
        match this.status {
            Status::Ready => Poll::Ready(Ok(())),
            // No self-wake: the adapter must return the bytes it already has.
            Status::Pending => Poll::Pending,
            Status::Error => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "original bounded provider error",
            ))),
        }
    }
}

impl AsyncReadVectored for Reader {}

#[test]
fn take_charges_pending_progress_and_preserves_the_callers_prefix() {
    let mut source = Reader::new(Status::Pending);
    let polls = Arc::clone(&source.polls);
    {
        let mut take = Take::new(&mut source, 5);
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = [0xa5; 5];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(b"P");
        assert!(matches!(Pin::new(&mut take).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
        assert_eq!(buf.filled(), b"Pabc");
        assert_eq!(take.limit(), 2);
        assert_eq!(storage[4], 0xa5);
        let mut rest = [0xa5; 5];
        let mut buf = ReadBuf::new(&mut rest);
        assert!(matches!(Pin::new(&mut take).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
        assert_eq!(buf.filled(), b"de");
        assert_eq!(take.limit(), 0);
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        let mut empty = [0; 8];
        let mut buf = ReadBuf::new(&mut empty);
        assert!(matches!(Pin::new(&mut take).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
        assert!(buf.filled().is_empty());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }
    assert_eq!(source.bytes, b"fghij");
}

#[test]
fn take_returns_original_error_but_never_reissues_consumed_quota() {
    let mut source = Reader::new(Status::Error);
    {
        let mut take = Take::new(&mut source, 5);
        let mut cx = Context::from_waker(Waker::noop());
        for (expected, remaining) in [(b"abc".as_slice(), 2), (b"de".as_slice(), 0)] {
            let mut storage = [0; 8];
            let mut buf = ReadBuf::new(&mut storage);
            let error = match Pin::new(&mut take).poll_read(&mut cx, &mut buf) {
                Poll::Ready(Err(error)) => error,
                _ => panic!("provider error was hidden"),
            };
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(error.to_string(), "original bounded provider error");
            assert_eq!(buf.filled(), expected);
            assert_eq!(take.limit(), remaining);
        }
    }
    assert_eq!(source.bytes, b"fghij");
}

#[test]
fn take_rejects_shifted_storage_for_every_provider_status_without_replay() {
    for status in [Status::Ready, Status::Pending, Status::Error] {
        let mut source = Reader::new(status);
        source.shifted = true;
        let polls = Arc::clone(&source.polls);
        let mut take = Take::new(source, 4);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            let mut storage = [0xa5; 8];
            let mut buf = ReadBuf::new(&mut storage);
            buf.put_slice(b"P");
            assert!(matches!(
                Pin::new(&mut take).poll_read(&mut cx, &mut buf),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
            ));
            assert_eq!(buf.filled(), b"P");
            assert_eq!(take.limit(), 4);
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn take_preserves_a_provider_panic_and_refuses_unknown_position_replay() {
    let mut source = Reader::new(Status::Ready);
    source.panics = true;
    let polls = Arc::clone(&source.polls);
    let mut take = Take::new(source, 4);
    let mut storage = [0; 8];
    let mut buf = ReadBuf::new(&mut storage);
    let mut cx = Context::from_waker(Waker::noop());
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Pin::new(&mut take).poll_read(&mut cx, &mut buf);
    }));
    let payload = failure.expect_err("provider panic must propagate");
    let message = payload.downcast_ref::<&str>().copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    assert_eq!(message, Some("bounded provider panic sentinel"));
    assert!(buf.filled().is_empty());
    assert_eq!(take.limit(), 4);
    assert!(matches!(
        Pin::new(&mut take).poll_read(&mut cx, &mut buf),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
    ));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

struct WaitOnce(bool);

impl AsyncRead for WaitOnce {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.0 {
            self.0 = true;
            Poll::Pending
        } else {
            buf.put_slice(b"x");
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncReadVectored for WaitOnce {}

#[test]
fn take_empty_polls_do_not_touch_source_and_empty_pending_is_not_eof() {
    let source = Reader::new(Status::Ready);
    let polls = Arc::clone(&source.polls);
    let mut zero = Take::new(source, 0);
    let mut cx = Context::from_waker(Waker::noop());
    let mut storage = [0; 8];
    assert!(matches!(Pin::new(&mut zero).poll_read(&mut cx, &mut ReadBuf::new(&mut storage)), Poll::Ready(Ok(()))));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let source = Reader::new(Status::Ready);
    let polls = Arc::clone(&source.polls);
    let mut take = Take::new(source, 9);
    assert!(matches!(Pin::new(&mut take).poll_read(&mut cx, &mut ReadBuf::new(&mut [])), Poll::Ready(Ok(()))));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let mut take = Take::new(WaitOnce(false), 1);
    let mut buf = ReadBuf::new(&mut storage);
    assert!(Pin::new(&mut take).poll_read(&mut cx, &mut buf).is_pending());
    assert_eq!(take.limit(), 1);
    assert!(buf.filled().is_empty());
    assert!(matches!(Pin::new(&mut take).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
    assert_eq!(buf.filled(), b"x");
    assert_eq!(take.limit(), 0);
}

#[test]
fn vectored_scalar_fallback_reports_pending_bytes_and_preserves_other_destinations() {
    let mut source = Reader::new(Status::Pending);
    let mut first = [0xa5; 4];
    let mut second = [0xa5; 4];
    let mut cx = Context::from_waker(Waker::noop());
    let mut bufs = [IoSliceMut::new(&mut []), IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    assert!(matches!(Pin::new(&mut source).poll_read_vectored(&mut cx, &mut bufs), Poll::Ready(Ok(3))));
    assert_eq!(&first, &[b'a', b'b', b'c', 0xa5]);
    assert_eq!(second, [0xa5; 4]);
    assert_eq!(source.bytes, b"defghij");
}

#[test]
fn vectored_scalar_fallback_rejects_shifted_storage_for_every_status() {
    for status in [Status::Ready, Status::Pending, Status::Error] {
        let mut source = Reader::new(status);
        source.shifted = true;
        let mut storage = [0xa5; 8];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let before = (bufs[0].as_ptr(), bufs[0].len());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut source).poll_read_vectored(&mut cx, &mut bufs),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert_eq!((bufs[0].as_ptr(), bufs[0].len()), before);
    }
}

#[test]
fn vectored_scalar_fallback_keeps_empty_pending_distinct_from_eof() {
    let mut source = WaitOnce(false);
    let mut storage = [0; 4];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut source).poll_read_vectored(&mut cx, &mut bufs).is_pending());
    assert!(matches!(Pin::new(&mut source).poll_read_vectored(&mut cx, &mut bufs), Poll::Ready(Ok(1))));
    assert_eq!(bufs[0][0], b'x');
}

#[test]
fn bounded_scalar_and_vectored_reads_agree_for_every_small_partition() {
    for status in [Status::Ready, Status::Pending] {
        for limit in 0..=12 {
            for width in 1..=7 {
                for chunk in 1..=5 {
                    let mut source = Reader::new(status);
                    source.chunk = chunk;
                    let mut take = Take::new(&mut source, limit);
                    let mut output = Vec::new();
                    let mut cx = Context::from_waker(Waker::noop());
                    for turn in 0..32 {
                        let mut storage = vec![0xa5; width];
                        let n = if turn % 2 == 0 {
                            let mut buf = ReadBuf::new(&mut storage);
                            assert!(matches!(Pin::new(&mut take).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
                            buf.filled().len()
                        } else {
                            let mut bufs = [IoSliceMut::new(&mut storage)];
                            match Pin::new(&mut take).poll_read_vectored(&mut cx, &mut bufs) {
                                Poll::Ready(Ok(n)) => n,
                                _ => panic!("positive fill must not park"),
                            }
                        };
                        output.extend_from_slice(&storage[..n]);
                        assert!(storage[n..].iter().all(|byte| *byte == 0xa5));
                        assert_eq!(take.limit(), limit - output.len() as u64);
                        if n == 0 { break; }
                    }
                    let expected = usize::try_from(limit).unwrap().min(10);
                    assert_eq!(output, &b"abcdefghij"[..expected]);
                }
            }
        }
    }
}
