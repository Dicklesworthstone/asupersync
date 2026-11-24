use super::*;
use crate::bytes::{Bytes, BytesCursor};
use crate::http::body::{Full, HeaderName, HeaderValue};
use crate::io::{AsyncWrite, copy_buf};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomPinned;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

type Step = Poll<Option<io::Result<Frame<BytesCursor>>>>;

struct ScriptBody {
    steps: VecDeque<Step>,
    polls: Rc<Cell<usize>>,
    drops: Rc<Cell<usize>>,
}

impl ScriptBody {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            polls: Rc::new(Cell::new(0)),
            drops: Rc::new(Cell::new(0)),
        }
    }
}

impl Body for ScriptBody {
    type Data = BytesCursor;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Step {
        let this = self.get_mut();
        this.polls.set(this.polls.get() + 1);
        this.steps.pop_front().expect("source was polled past EOF")
    }
}

impl Drop for ScriptBody {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn data(bytes: &'static [u8]) -> Step {
    Poll::Ready(Some(Ok(Frame::data(BytesCursor::new(Bytes::from_static(
        bytes,
    ))))))
}

fn trailers() -> Step {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("digest"),
        HeaderValue::from_static("finished"),
    );
    Poll::Ready(Some(Ok(Frame::trailers(headers))))
}

fn read_now<B>(reader: &mut BodyReader<B>, capacity: usize) -> io::Result<Vec<u8>>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut storage = vec![0; capacity];
    let mut buf = ReadBuf::new(&mut storage);
    let mut cx = Context::from_waker(Waker::noop());
    match Pin::new(reader).poll_read(&mut cx, &mut buf) {
        Poll::Ready(Ok(())) => Ok(buf.filled().to_vec()),
        Poll::Ready(Err(error)) => Err(error),
        Poll::Pending => panic!("expected a ready read"),
    }
}

#[test]
fn partial_reads_retain_frames_and_release_source_at_real_eof() {
    let source = ScriptBody::new([data(b"abcdef"), data(b"gh"), Poll::Ready(None)]);
    let polls = Rc::clone(&source.polls);
    let drops = Rc::clone(&source.drops);
    let mut reader = BodyReader::new(source);
    assert_eq!(read_now(&mut reader, 2).unwrap(), b"ab");
    assert_eq!(read_now(&mut reader, 8).unwrap(), b"cdef");
    assert_eq!(polls.get(), 1);
    assert_eq!(drops.get(), 0);
    assert_eq!(read_now(&mut reader, 8).unwrap(), b"gh");
    assert!(read_now(&mut reader, 8).unwrap().is_empty());
    assert!(reader.is_terminated());
    assert!(reader.get_ref().is_none());
    assert_eq!(drops.get(), 1);
    assert!(read_now(&mut reader, 8).unwrap().is_empty());
    assert_eq!(polls.get(), 3);
}

#[test]
fn buffered_reads_borrow_original_storage_and_clamp_consumption() {
    let bytes = Bytes::from_static(b"hello");
    let original = bytes.as_slice().as_ptr();
    let mut reader = BodyReader::new(bytes);
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(slice)) = Pin::new(&mut reader).poll_fill_buf(&mut cx) else {
        panic!("expected buffered bytes");
    };
    assert_eq!(slice.as_ptr(), original);
    assert_eq!(slice, b"hello");
    Pin::new(&mut reader).consume(2);
    assert_eq!(read_now(&mut reader, 1).unwrap(), b"l");
    Pin::new(&mut reader).consume(usize::MAX);
    assert!(read_now(&mut reader, 8).unwrap().is_empty());
}

#[test]
fn fragmented_buffers_do_not_lose_the_second_contiguous_chunk() {
    let first: &[u8] = b"first";
    let second: &[u8] = b"second";
    let mut reader = BodyReader::new(Full::new(first.chain(second)));
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(slice)) = Pin::new(&mut reader).poll_fill_buf(&mut cx) else {
        panic!("expected first contiguous chunk");
    };
    assert_eq!(slice, b"first");
    Pin::new(&mut reader).consume(usize::MAX);
    assert_eq!(read_now(&mut reader, 32).unwrap(), b"second");
    assert!(read_now(&mut reader, 32).unwrap().is_empty());
}

#[test]
fn trailers_are_retained_while_waiting_for_actual_eof() {
    let source = ScriptBody::new([
        data(b""),
        data(b"body"),
        trailers(),
        Poll::Pending,
        Poll::Ready(None),
    ]);
    let drops = Rc::clone(&source.drops);
    let mut reader = BodyReader::new(source);
    assert_eq!(read_now(&mut reader, 8).unwrap(), b"body");
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut reader).poll_fill_buf(&mut cx).is_pending());
    assert!(!reader.is_terminated());
    assert_eq!(drops.get(), 0);
    assert_eq!(reader.trailers().unwrap().len(), 1);
    assert_eq!(reader.take_trailers().unwrap().len(), 1);
    assert!(reader.trailers().is_none());
    assert!(read_now(&mut reader, 8).unwrap().is_empty());
    assert_eq!(drops.get(), 1);
}

#[test]
fn taking_trailers_cannot_bypass_frame_order_validation() {
    for invalid in [data(b"late"), data(b""), trailers()] {
        let source = ScriptBody::new([trailers(), Poll::Pending, invalid]);
        let polls = Rc::clone(&source.polls);
        let drops = Rc::clone(&source.drops);
        let mut reader = BodyReader::new(source);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut reader).poll_fill_buf(&mut cx).is_pending());
        assert!(reader.take_trailers().is_some());
        let error = read_now(&mut reader, 8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(drops.get(), 1);
        assert!(read_now(&mut reader, 8).unwrap().is_empty());
        assert_eq!(polls.get(), 3);
    }
}

#[test]
fn source_error_follows_delivered_bytes_and_preserves_io_kind_and_payload() {
    #[derive(Debug)]
    struct Marker;
    impl fmt::Display for Marker {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("source marker")
        }
    }
    impl std::error::Error for Marker {}

    let source = ScriptBody::new([
        data(b"prefix"),
        Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::Interrupted, Marker)))),
    ]);
    let drops = Rc::clone(&source.drops);
    let mut reader = BodyReader::new(source);
    assert_eq!(read_now(&mut reader, 64).unwrap(), b"prefix");
    let error = read_now(&mut reader, 64).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(error.get_ref().unwrap().is::<Marker>());
    assert_eq!(drops.get(), 1);
    assert!(read_now(&mut reader, 64).unwrap().is_empty());
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn immediately_ready_empty_frames_yield_and_wake_without_false_eof() {
    let source = ScriptBody::new(
        std::iter::repeat_with(|| data(b""))
            .take(MAX_FRAMES_PER_POLL)
            .chain([data(b"after yield"), Poll::Ready(None)]),
    );
    let polls = Rc::clone(&source.polls);
    let mut reader = BodyReader::new(source);
    let wake_count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wake_count));
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut reader).poll_fill_buf(&mut cx).is_pending());
    assert_eq!(polls.get(), MAX_FRAMES_PER_POLL);
    assert_eq!(wake_count.0.load(Ordering::Relaxed), 1);
    assert_eq!(read_now(&mut reader, 32).unwrap(), b"after yield");
}

#[test]
fn empty_destination_does_not_poll_or_release_the_source() {
    let source = ScriptBody::new([data(b"ready")]);
    let polls = Rc::clone(&source.polls);
    let drops = Rc::clone(&source.drops);
    let mut reader = BodyReader::new(source);
    assert!(read_now(&mut reader, 0).unwrap().is_empty());
    assert_eq!(polls.get(), 0);
    assert_eq!(drops.get(), 0);
    drop(reader);
    assert_eq!(drops.get(), 1);
}

#[test]
fn a_pinned_non_send_body_needs_no_unsafe_projection() {
    struct PinnedBody {
        source: RefCell<ScriptBody>,
        _pin: PhantomPinned,
    }
    impl Body for PinnedBody {
        type Data = BytesCursor;
        type Error = io::Error;

        fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Step {
            Pin::new(&mut *self.as_ref().get_ref().source.borrow_mut()).poll_frame(cx)
        }
    }
    let mut reader = BodyReader::new(PinnedBody {
        source: RefCell::new(ScriptBody::new([data(b"pinned"), Poll::Ready(None)])),
        _pin: PhantomPinned,
    });
    assert_eq!(read_now(&mut reader, 32).unwrap(), b"pinned");
    assert!(read_now(&mut reader, 32).unwrap().is_empty());
}

struct PausingWriter {
    bytes: Vec<u8>,
    pause: bool,
}

impl AsyncWrite for PausingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pause {
            return Poll::Pending;
        }
        let count = buf.len().min(2);
        this.bytes.extend_from_slice(&buf[..count]);
        this.pause = true;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn dropped_copy_buf_wait_preserves_unwritten_data_and_trailers() {
    let mut reader = BodyReader::new(ScriptBody::new([
        data(b"abcdef"),
        trailers(),
        Poll::Ready(None),
    ]));
    let mut writer = PausingWriter {
        bytes: Vec::new(),
        pause: false,
    };
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut copy = copy_buf(&mut reader, &mut writer);
        assert!(Pin::new(&mut copy).poll(&mut cx).is_pending());
    }
    assert_eq!(writer.bytes, b"ab");
    let mut rest = Vec::new();
    let mut copy = copy_buf(&mut reader, &mut rest);
    assert!(matches!(
        Pin::new(&mut copy).poll(&mut cx),
        Poll::Ready(Ok(4))
    ));
    assert_eq!(rest, b"cdef");
    assert_eq!(reader.trailers().unwrap().len(), 1);
    assert!(reader.is_terminated());
}

#[test]
fn caught_source_panic_releases_without_repolling_unknown_effects() {
    struct PanicBody(Rc<Cell<usize>>);
    impl Body for PanicBody {
        type Data = BytesCursor;
        type Error = io::Error;

        fn poll_frame(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Step {
            self.0.set(self.0.get() + 1);
            panic!("source advanced before panicking");
        }
    }
    let polls = Rc::new(Cell::new(0));
    let mut reader = BodyReader::new(PanicBody(Rc::clone(&polls)));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = read_now(&mut reader, 8);
    }))
    .is_err());
    assert_eq!(
        read_now(&mut reader, 8).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(reader.is_terminated());
    assert!(read_now(&mut reader, 8).unwrap().is_empty());
    assert_eq!(polls.get(), 1);
}
