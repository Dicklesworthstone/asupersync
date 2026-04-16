//! Async framed reader combining `AsyncRead` with a `Decoder`.

use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::io::{AsyncRead, ReadBuf};
use crate::stream::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default read buffer capacity.
const DEFAULT_CAPACITY: usize = 8192;

/// Stack buffer size for reads.
const READ_BUF_SIZE: usize = 8192;
/// Cooperative cap on repeated read/decode passes inside one `poll_next`.
///
/// Without this bound, an always-ready reader that never produces a full frame
/// can monopolize a single executor turn indefinitely.
const MAX_READ_PASSES_PER_POLL: usize = 32;

/// Async framed reader that applies a `Decoder` to an `AsyncRead` source.
///
/// Implements `Stream` where each item is a decoded frame. Data is read
/// from the inner reader into an internal buffer, then the decoder extracts
/// complete frames.
///
/// # Cancel Safety
///
/// `poll_next` is cancel-safe. Partial data remains in the internal buffer
/// across cancellations. No decoded frame is lost unless it was already yielded.
pub struct FramedRead<R, D> {
    inner: R,
    decoder: D,
    buffer: BytesMut,
    eof: bool,
}

impl<R, D> FramedRead<R, D> {
    /// Creates a new `FramedRead` with the default buffer capacity.
    #[inline]
    pub fn new(inner: R, decoder: D) -> Self {
        Self::with_capacity(inner, decoder, DEFAULT_CAPACITY)
    }

    /// Creates a new `FramedRead` with the specified buffer capacity.
    pub fn with_capacity(inner: R, decoder: D, capacity: usize) -> Self {
        Self {
            inner,
            decoder,
            buffer: BytesMut::with_capacity(capacity),
            eof: false,
        }
    }

    /// Returns a reference to the underlying reader.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Returns a reference to the decoder.
    #[inline]
    #[must_use]
    pub fn decoder(&self) -> &D {
        &self.decoder
    }

    /// Returns a mutable reference to the decoder.
    pub fn decoder_mut(&mut self) -> &mut D {
        &mut self.decoder
    }

    /// Returns a reference to the read buffer.
    #[inline]
    #[must_use]
    pub fn read_buffer(&self) -> &BytesMut {
        &self.buffer
    }

    /// Consumes `self` and returns the inner reader.
    #[inline]
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consumes `self` and returns the inner reader, decoder, and buffer.
    pub fn into_parts(self) -> (R, D, BytesMut) {
        (self.inner, self.decoder, self.buffer)
    }
}

impl<R, D> Stream for FramedRead<R, D>
where
    R: AsyncRead + Unpin,
    D: Decoder + Unpin,
{
    type Item = Result<D::Item, D::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut read_passes = 0usize;
        let mut should_yield = false;

        loop {
            // Try to decode a frame from buffered data.
            match this.decoder.decode(&mut this.buffer) {
                Ok(Some(item)) => return Poll::Ready(Some(Ok(item))),
                Ok(None) => {
                    if should_yield {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                } // Need more data
                Err(e) => return Poll::Ready(Some(Err(e))),
            }

            // If we hit EOF, give the decoder one last chance.
            if this.eof {
                return match this.decoder.decode_eof(&mut this.buffer) {
                    Ok(Some(item)) => Poll::Ready(Some(Ok(item))),
                    Ok(None) => Poll::Ready(None),
                    Err(e) => Poll::Ready(Some(Err(e))),
                };
            }

            // Read more data from the underlying reader.
            let mut tmp = [0u8; READ_BUF_SIZE];
            let mut read_buf = ReadBuf::new(&mut tmp);

            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        // Loop back to handle EOF decoding.
                    } else {
                        this.buffer.put_slice(filled);
                        read_passes += 1;
                        if read_passes >= MAX_READ_PASSES_PER_POLL {
                            should_yield = true;
                        }
                        // Loop back to try decoding.
                    }
                }
            }
        }
    }
}

impl<R: std::fmt::Debug, D: std::fmt::Debug> std::fmt::Debug for FramedRead<R, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedRead")
            .field("inner", &self.inner)
            .field("decoder", &self.decoder)
            .field("buffer_len", &self.buffer.len())
            .field("eof", &self.eof)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{LinesCodec, LinesCodecError};
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct TrackWaker(Arc<AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn track_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(TrackWaker(flag)))
    }

    /// A reader that yields all data immediately.
    struct SliceReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl SliceReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
            }
        }
    }

    impl AsyncRead for SliceReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let remaining = &this.data[this.pos..];
            if remaining.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_read_decodes_lines() {
        let reader = SliceReader::new(b"hello\nworld\n");
        let mut framed = FramedRead::new(reader, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "hello"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "world"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_read_handles_partial_data() {
        // Data without trailing newline is emitted by decode_eof.
        let reader = SliceReader::new(b"partial");
        let mut framed = FramedRead::new(reader, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "partial"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_read_empty_input() {
        let reader = SliceReader::new(b"");
        let mut framed = FramedRead::new(reader, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_read_accessors() {
        let reader = SliceReader::new(b"");
        let mut framed = FramedRead::new(reader, LinesCodec::new());

        assert!(framed.read_buffer().is_empty());
        let _decoder = framed.decoder();
        let _decoder_mut = framed.decoder_mut();
        let _reader = framed.get_ref();
        let _reader_mut = framed.get_mut();
    }

    #[test]
    fn framed_read_into_parts() {
        let reader = SliceReader::new(b"leftover");
        let framed = FramedRead::new(reader, LinesCodec::new());

        let (_reader, _decoder, _buf) = framed.into_parts();
    }

    /// Reader that yields data in small chunks to test multi-read decoding.
    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        index: usize,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<&[u8]>) -> Self {
            Self {
                chunks: chunks.into_iter().map(<[u8]>::to_vec).collect(),
                index: 0,
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.index >= this.chunks.len() {
                return Poll::Ready(Ok(()));
            }
            let chunk = &this.chunks[this.index];
            let to_copy = std::cmp::min(chunk.len(), buf.remaining());
            buf.put_slice(&chunk[..to_copy]);
            this.index += 1;
            Poll::Ready(Ok(()))
        }
    }

    struct ErrorReader {
        kind: io::ErrorKind,
    }

    impl ErrorReader {
        fn new(kind: io::ErrorKind) -> Self {
            Self { kind }
        }
    }

    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let kind = self.get_mut().kind;
            Poll::Ready(Err(io::Error::new(kind, "framed read test error")))
        }
    }

    struct AlwaysReadyByteReader {
        reads: usize,
        panic_after: usize,
    }

    impl AlwaysReadyByteReader {
        fn new(panic_after: usize) -> Self {
            Self {
                reads: 0,
                panic_after,
            }
        }
    }

    impl AsyncRead for AlwaysReadyByteReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            assert!(
                this.reads < this.panic_after,
                "reader was polled too many times without yielding"
            );
            this.reads += 1;
            buf.put_slice(b"a");
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_read_multi_chunk() {
        let reader = ChunkedReader::new(vec![b"hel", b"lo\nwo", b"rld\n"]);
        let mut framed = FramedRead::new(reader, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "hello"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "world"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_read_yields_cooperatively_on_always_ready_reader() {
        let reader = AlwaysReadyByteReader::new(MAX_READ_PASSES_PER_POLL + 1);
        let mut framed = FramedRead::new(reader, LinesCodec::new());
        let woke = Arc::new(AtomicBool::new(false));
        let waker = track_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        assert!(
            woke.load(Ordering::SeqCst),
            "cooperative yield should self-wake for continued draining"
        );
        assert_eq!(
            framed.get_ref().reads,
            MAX_READ_PASSES_PER_POLL,
            "poll_next should stop after the cooperative read budget"
        );
        assert_eq!(
            framed.read_buffer().len(),
            MAX_READ_PASSES_PER_POLL,
            "already-read bytes must stay buffered across the cooperative yield"
        );
    }

    #[test]
    fn framed_read_preserves_io_error_kind_from_lines_codec() {
        let reader = ErrorReader::new(io::ErrorKind::BrokenPipe);
        let mut framed = FramedRead::new(reader, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        match poll {
            Poll::Ready(Some(Err(LinesCodecError::Io(err)))) => {
                assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected io error propagation, got {other:?}"),
        }
    }
}
