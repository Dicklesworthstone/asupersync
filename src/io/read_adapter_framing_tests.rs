//! Shared read-contract regressions for the one-way and duplex framed readers.

use super::{Reader, Status};
use crate::bytes::BytesMut;
use crate::codec::{Framed, FramedRead, LengthDelimitedCodec};
use crate::io::{AsyncRead, ReadBuf};
use crate::stream::Stream;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const WIRE: &[u8] = b"\0\0\0\x05hello";

enum Adapter<R> {
    Read(FramedRead<R, LengthDelimitedCodec>),
    Duplex(Framed<R, LengthDelimitedCodec>),
}

impl<R: AsyncRead + Unpin> Adapter<R> {
    fn new(reader: R, duplex: bool, maximum: usize) -> Self {
        let codec = LengthDelimitedCodec::new();
        if duplex {
            Self::Duplex(Framed::new(reader, codec).with_max_buffer_len(maximum))
        } else {
            Self::Read(FramedRead::new(reader, codec).with_max_buffer_len(maximum))
        }
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<BytesMut>>> {
        match self {
            Self::Read(reader) => Pin::new(reader).poll_next(cx),
            Self::Duplex(reader) => Pin::new(reader).poll_next(cx),
        }
    }

    fn buffer(&self) -> &[u8] {
        match self {
            Self::Read(reader) => reader.read_buffer().as_ref(),
            Self::Duplex(reader) => reader.read_buffer().as_ref(),
        }
    }

    fn into_buffer(self) -> BytesMut {
        match self {
            Self::Read(reader) => reader.into_parts().2,
            Self::Duplex(reader) => reader.into_parts().read_buf,
        }
    }
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn source(status: Status) -> Reader {
    let mut reader = Reader::new(status);
    reader.bytes = WIRE;
    reader.chunk = WIRE.len();
    reader
}

#[test]
fn pending_fill_delivers_complete_frames_without_another_wake() {
    for duplex in [false, true] {
        let reader = source(Status::Pending);
        let polls = Arc::clone(&reader.polls);
        let mut adapter = Adapter::new(reader, duplex, WIRE.len());
        let wakes = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            adapter.poll_next(&mut cx),
            Poll::Ready(Some(Ok(frame))) if frame.as_ref() == b"hello"
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        assert!(adapter.buffer().is_empty());
        assert!(matches!(adapter.poll_next(&mut cx), Poll::Ready(None)));
    }
}

#[test]
fn fragmented_pending_progress_yields_and_survives_dropped_waits() {
    const LONG_WIRE: [u8; 68] = {
        let mut bytes = [b'x'; 68];
        bytes[0] = 0;
        bytes[1] = 0;
        bytes[2] = 0;
        bytes[3] = 64;
        bytes
    };
    for duplex in [false, true] {
        let mut reader = source(Status::Pending);
        reader.bytes = &LONG_WIRE;
        reader.chunk = 1;
        let polls = Arc::clone(&reader.polls);
        let mut adapter = Adapter::new(reader, duplex, LONG_WIRE.len());
        let wakes = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        for expected_reads in [32, 64] {
            {
                let mut wait = std::pin::pin!(poll_fn(|cx| adapter.poll_next(cx)));
                assert!(wait.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(polls.load(Ordering::SeqCst), expected_reads);
            assert_eq!(adapter.buffer(), &LONG_WIRE[..expected_reads]);
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
        assert!(matches!(
            adapter.poll_next(&mut cx),
            Poll::Ready(Some(Ok(frame))) if frame.as_ref() == &LONG_WIRE[4..]
        ));
        assert_eq!(polls.load(Ordering::SeqCst), LONG_WIRE.len());
        assert!(matches!(adapter.poll_next(&mut cx), Poll::Ready(None)));
    }
}

struct PausedReader {
    reader: Reader,
    prefix_sent: bool,
    released: Arc<AtomicBool>,
}

impl AsyncRead for PausedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_sent && !this.released.load(Ordering::SeqCst) {
            // The test releases this gate and explicitly wakes its task.
            return Poll::Pending;
        }
        this.prefix_sent = true;
        Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}

#[test]
fn empty_pending_keeps_partial_prefix_without_spinning_or_claiming_eof() {
    for duplex in [false, true] {
        let mut reader = source(Status::Pending);
        reader.chunk = 3;
        let polls = Arc::clone(&reader.polls);
        let released = Arc::new(AtomicBool::new(false));
        let reader = PausedReader {
            reader,
            prefix_sent: false,
            released: Arc::clone(&released),
        };
        let mut adapter = Adapter::new(reader, duplex, WIRE.len());
        let wakes = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        {
            let mut wait = std::pin::pin!(poll_fn(|cx| adapter.poll_next(cx)));
            assert!(wait.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(adapter.buffer(), &WIRE[..3]);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        released.store(true, Ordering::SeqCst);
        waker.wake_by_ref();
        assert!(matches!(
            adapter.poll_next(&mut cx),
            Poll::Ready(Some(Ok(frame))) if frame.as_ref() == b"hello"
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 3);
    }
}

#[test]
fn read_errors_preserve_filled_bytes_and_original_error_without_decoding() {
    for duplex in [false, true] {
        let reader = source(Status::Error);
        let polls = Arc::clone(&reader.polls);
        let mut adapter = Adapter::new(reader, duplex, WIRE.len());
        let mut cx = Context::from_waker(Waker::noop());
        let error = match adapter.poll_next(&mut cx) {
            Poll::Ready(Some(Err(error))) => error,
            _ => panic!("framing hid the provider error"),
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "original bounded provider error");
        assert_eq!(adapter.buffer(), WIRE);
        assert!(matches!(adapter.poll_next(&mut cx), Poll::Ready(None)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.into_buffer().as_ref(), WIRE);
    }
}

#[test]
fn shifted_storage_is_rejected_for_every_status_without_repolling() {
    for duplex in [false, true] {
        for status in [Status::Ready, Status::Pending, Status::Error] {
            let mut reader = source(status);
            reader.shifted = true;
            let polls = Arc::clone(&reader.polls);
            let mut adapter = Adapter::new(reader, duplex, WIRE.len());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                adapter.poll_next(&mut cx),
                Poll::Ready(Some(Err(error))) if error.kind() == io::ErrorKind::InvalidData
            ));
            assert!(adapter.buffer().is_empty());
            assert!(matches!(adapter.poll_next(&mut cx), Poll::Ready(None)));
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn provider_panics_propagate_and_leave_framed_readers_terminal() {
    for duplex in [false, true] {
        let mut reader = source(Status::Ready);
        reader.panics = true;
        let polls = Arc::clone(&reader.polls);
        let mut adapter = Adapter::new(reader, duplex, WIRE.len());
        let mut cx = Context::from_waker(Waker::noop());
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = adapter.poll_next(&mut cx);
        }));
        let payload = failure.expect_err("provider panic must propagate");
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("bounded provider panic sentinel"));
        assert!(matches!(adapter.poll_next(&mut cx), Poll::Ready(None)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn pending_fills_never_grow_past_the_partial_frame_cap() {
    for duplex in [false, true] {
        let mut reader = source(Status::Pending);
        reader.chunk = 3;
        let polls = Arc::clone(&reader.polls);
        let mut adapter = Adapter::new(reader, duplex, 8);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            adapter.poll_next(&mut cx),
            Poll::Ready(Some(Err(error))) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert_eq!(adapter.buffer(), &WIRE[..8]);
        assert!(matches!(adapter.poll_next(&mut cx), Poll::Ready(None)));
        assert_eq!(polls.load(Ordering::SeqCst), 4);
    }
}
