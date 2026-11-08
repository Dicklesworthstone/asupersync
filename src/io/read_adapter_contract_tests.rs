//! Tests under `read_buf` can move its private backing slice to model an
//! invalid reader entirely in safe Rust, without leaked test allocations.

use super::ReadBuf;
use crate::io::{AsyncRead, AsyncReadVectored, Take};
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

#[path = "read_adapter_framing_tests.rs"]
mod framing;

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

#[test]
fn reader_body_rejects_shifted_storage_for_every_status_and_never_repolls() {
    use crate::http::body::{Body, ReaderBody};

    for status in [Status::Ready, Status::Pending, Status::Error] {
        let mut source = Reader::new(status);
        source.shifted = true;
        let polls = Arc::clone(&source.polls);
        let mut body = ReaderBody::with_capacity(source, 8);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(Some(Err(error))) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert_eq!(body.get_ref().bytes, b"defghij");
        for _ in 0..3 {
            assert!(matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Ready(None)));
        }
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn reader_body_accepts_filled_bytes_in_a_shorter_original_prefix() {
    use crate::bytes::Buf;
    use crate::http::body::{Body, Frame, ReaderBody};

    struct PrefixReader {
        done: bool,
    }

    impl AsyncRead for PrefixReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if !this.done {
                this.done = true;
                let storage = std::mem::replace(buf, ReadBuf::new(&mut [])).buf;
                *buf = ReadBuf::new(&mut storage[..3]);
                buf.put_slice(b"abc");
            }
            Poll::Ready(Ok(()))
        }
    }

    let mut body = ReaderBody::with_capacity(PrefixReader { done: false }, 8);
    let mut cx = Context::from_waker(Waker::noop());
    let data = match Pin::new(&mut body).poll_frame(&mut cx) {
        Poll::Ready(Some(Ok(Frame::Data(data)))) => data,
        other => panic!("valid original-buffer prefix was rejected: {other:?}"),
    };
    assert_eq!(data.remaining(), 3);
    assert_eq!(data.chunk(), b"abc");
    assert!(matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Ready(None)));
}

#[cfg(feature = "zstd")]
mod zstd {
    use super::{Reader, Status};
    use crate::compression::zstd::{DecodeLimits, ZstdDecoder};
    use crate::io::read_buf::copy_read_contract_tests::{
        ReadStep, ScriptReader, Status as ReadStatus, finish,
    };
    use crate::io::{AsyncRead, AsyncReadExt, ReadBuf};
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    // Independent RFC 8878 raw-block fixtures, not output from our encoder.
    const HI: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 2, 0x11, 0, 0, b'h', b'i'];
    const EMPTY: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0];
    const SKIPPABLE: &[u8] = &[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];

    #[test]
    fn pending_compressed_fills_survive_a_dropped_read_at_every_boundary() {
        for split in 1..HI.len() {
            let source = ScriptReader::new([
                ReadStep::Data(HI[..split].to_vec(), ReadStatus::Pending),
                ReadStep::Wait,
                ReadStep::Data(HI[split..].to_vec(), ReadStatus::Ready),
                ReadStep::Eof,
            ]);
            let polls = Rc::clone(&source.polls);
            let mut decoder = ZstdDecoder::new(source, DecodeLimits::new(2));
            let mut cx = Context::from_waker(Waker::noop());
            let mut storage = [0xa5; 8];
            {
                let mut read = decoder.read(&mut storage);
                assert!(Pin::new(&mut read).poll(&mut cx).is_pending());
            }
            assert_eq!(polls.get(), 2, "the reported prefix must be retained");
            assert_eq!(storage, [0xa5; 8]);
            let mut output = Vec::new();
            assert_eq!(finish(&mut decoder.read_to_end(&mut output)).unwrap(), 2);
            assert_eq!(output, b"hi", "split {split}");
            assert_eq!(polls.get(), 4);
        }
    }

    #[test]
    fn pending_compressed_fills_do_not_wait_for_another_source_wake() {
        let source = ScriptReader::new([
            ReadStep::Data(HI.to_vec(), ReadStatus::Pending),
            ReadStep::Eof,
        ]);
        let polls = Rc::clone(&source.polls);
        let mut decoder = ZstdDecoder::new(source, DecodeLimits::new(2));
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = [0xa5; 8];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(b"P");
        assert!(matches!(
            Pin::new(&mut decoder).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"Phi");
        assert_eq!(polls.get(), 1);
    }

    #[test]
    fn compressed_fills_are_retained_when_the_original_source_error_is_returned() {
        for split in 1..=HI.len() {
            let source = ScriptReader::new([
                ReadStep::Data(HI[..split].to_vec(), ReadStatus::Error),
                ReadStep::Data(HI[split..].to_vec(), ReadStatus::Ready),
                ReadStep::Eof,
            ]);
            let mut decoder = ZstdDecoder::new(source, DecodeLimits::new(2));
            let mut storage = [0xa5; 8];
            let error = finish(&mut decoder.read(&mut storage)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(error.to_string(), "scripted read error");
            assert_eq!(storage, [0xa5; 8]);
            let mut output = Vec::new();
            assert_eq!(finish(&mut decoder.read_to_end(&mut output)).unwrap(), 2);
            assert_eq!(output, b"hi", "split {split}");
        }
    }

    #[test]
    fn substituted_compressed_input_is_terminal_for_every_source_status() {
        for status in [Status::Ready, Status::Pending, Status::Error] {
            let mut source = Reader::new(status);
            source.bytes = HI;
            source.shifted = true;
            let polls = Arc::clone(&source.polls);
            let mut decoder = ZstdDecoder::new(source, DecodeLimits::new(2));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..3 {
                let mut storage = [0xa5; 8];
                let mut buf = ReadBuf::new(&mut storage);
                assert!(matches!(
                    Pin::new(&mut decoder).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
                ));
                assert!(buf.filled().is_empty());
                assert_eq!(storage, [0xa5; 8]);
            }
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        }
    }

    #[derive(Default)]
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn empty_and_skippable_frames_yield_then_resume_without_false_eof() {
        for frame in [EMPTY, SKIPPABLE] {
            let source = ScriptReader::new(
                (0..256)
                    .map(|_| ReadStep::Data(frame.to_vec(), ReadStatus::Ready))
                    .chain([
                        ReadStep::Data(HI.to_vec(), ReadStatus::Ready),
                        ReadStep::Eof,
                    ]),
            );
            let polls = Rc::clone(&source.polls);
            let mut decoder = ZstdDecoder::new(source, DecodeLimits::new(2));
            let wake = Arc::new(CountWake::default());
            let waker = Waker::from(Arc::clone(&wake));
            let mut cx = Context::from_waker(&waker);
            let mut storage = [0xa5; 8];
            let mut buf = ReadBuf::new(&mut storage);
            buf.put_slice(b"P");
            assert!(Pin::new(&mut decoder).poll_read(&mut cx, &mut buf).is_pending());
            assert_eq!(buf.filled(), b"P");
            assert!((1..=32).contains(&polls.get()), "one bounded read poll");
            assert_eq!(wake.0.load(Ordering::SeqCst), 1);
            let mut output = Vec::new();
            assert_eq!(finish(&mut decoder.read_to_end(&mut output)).unwrap(), 2);
            assert_eq!(output, b"hi");
            assert_eq!(polls.get(), 258);
        }
    }
}
