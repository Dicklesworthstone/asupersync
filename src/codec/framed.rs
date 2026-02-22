//! Full-duplex framed transport combining `AsyncRead` + `AsyncWrite` with a codec.

use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::stream::Stream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer capacity for both read and write.
const DEFAULT_CAPACITY: usize = 8192;

/// Stack buffer size for reads.
const READ_BUF_SIZE: usize = 8192;

/// Full-duplex framed transport.
///
/// Combines an `AsyncRead + AsyncWrite` transport with a codec that
/// implements both `Decoder` and `Encoder`. The read half implements
/// `Stream` for receiving decoded frames. The write half provides
/// `send`/`poll_flush`/`poll_close` for sending encoded frames.
///
/// # Cancel Safety
///
/// - Reading (`poll_next`): cancel-safe. Partial data stays in the read buffer.
/// - Writing (`send`): synchronous encoding, always completes.
/// - Flushing (`poll_flush`): cancel-safe. Partial writes resume on next call.
pub struct Framed<T, U> {
    inner: T,
    codec: U,
    read_buf: BytesMut,
    write_buf: BytesMut,
    eof: bool,
}

impl<T, U> Framed<T, U> {
    /// Creates a new `Framed` with default buffer capacity.
    pub fn new(inner: T, codec: U) -> Self {
        Self::with_capacity(inner, codec, DEFAULT_CAPACITY)
    }

    /// Creates a new `Framed` with the specified buffer capacity for both
    /// read and write buffers.
    pub fn with_capacity(inner: T, codec: U, capacity: usize) -> Self {
        Self {
            inner,
            codec,
            read_buf: BytesMut::with_capacity(capacity),
            write_buf: BytesMut::with_capacity(capacity),
            eof: false,
        }
    }

    /// Returns a reference to the underlying transport.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns a reference to the codec.
    #[must_use]
    pub fn codec(&self) -> &U {
        &self.codec
    }

    /// Returns a mutable reference to the codec.
    pub fn codec_mut(&mut self) -> &mut U {
        &mut self.codec
    }

    /// Returns a reference to the read buffer.
    #[must_use]
    pub fn read_buffer(&self) -> &BytesMut {
        &self.read_buf
    }

    /// Returns a reference to the write buffer.
    #[must_use]
    pub fn write_buffer(&self) -> &BytesMut {
        &self.write_buf
    }

    /// Consumes `self` and returns the transport and codec.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Consumes `self` and returns all parts.
    pub fn into_parts(self) -> FramedParts<T, U> {
        FramedParts {
            inner: self.inner,
            codec: self.codec,
            read_buf: self.read_buf,
            write_buf: self.write_buf,
        }
    }
}

/// Parts of a deconstructed `Framed`.
pub struct FramedParts<T, U> {
    /// The underlying transport.
    pub inner: T,
    /// The codec.
    pub codec: U,
    /// Unprocessed read data.
    pub read_buf: BytesMut,
    /// Unsent write data.
    pub write_buf: BytesMut,
}

// --- Stream (read) implementation ---

impl<T, U> Stream for Framed<T, U>
where
    T: AsyncRead + Unpin,
    U: Decoder + Unpin,
{
    type Item = Result<<U as Decoder>::Item, <U as Decoder>::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // Try to decode a frame from buffered data.
            if !this.eof {
                match this.codec.decode(&mut this.read_buf) {
                    Ok(Some(item)) => return Poll::Ready(Some(Ok(item))),
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Some(Err(e))),
                }
            }

            // EOF: give decoder one last chance.
            if this.eof {
                return match this.codec.decode_eof(&mut this.read_buf) {
                    Ok(Some(item)) => Poll::Ready(Some(Ok(item))),
                    Ok(None) => Poll::Ready(None),
                    Err(e) => Poll::Ready(Some(Err(e))),
                };
            }

            // Read more data.
            let mut tmp = [0u8; READ_BUF_SIZE];
            let mut read_buf = ReadBuf::new(&mut tmp);

            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                    } else {
                        this.read_buf.put_slice(filled);
                    }
                }
            }
        }
    }
}

// --- Write (sink) methods ---

impl<T, U> Framed<T, U> {
    /// Encode an item into the write buffer.
    ///
    /// The encoded data is buffered internally. Call `poll_flush` to write
    /// it to the underlying transport.
    pub fn send<I>(&mut self, item: I) -> Result<(), <U as Encoder<I>>::Error>
    where
        U: Encoder<I>,
    {
        self.codec.encode(item, &mut self.write_buf)
    }
}

impl<T, U> Framed<T, U>
where
    T: AsyncWrite + Unpin,
{
    /// Flush all buffered write data to the underlying transport.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write frame to transport",
                )));
            }
            let _ = self.write_buf.split_to(n);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Flush all buffered data and shut down the transport.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: std::fmt::Debug, U: std::fmt::Debug> std::fmt::Debug for Framed<T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framed")
            .field("inner", &self.inner)
            .field("codec", &self.codec)
            .field("read_buf_len", &self.read_buf.len())
            .field("write_buf_len", &self.write_buf.len())
            .field("eof", &self.eof)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::LinesCodec;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    /// Duplex transport backed by separate read and write buffers.
    #[derive(Debug)]
    struct DuplexBuf {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl DuplexBuf {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_data: read_data.to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for DuplexBuf {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let remaining = &this.read_data[this.read_pos..];
            if remaining.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.read_pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DuplexBuf {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_read_and_write() {
        let transport = DuplexBuf::new(b"incoming\n");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Read a frame.
        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "incoming"));

        // Write a frame.
        framed.send("outgoing".to_string()).unwrap();
        let poll = framed.poll_flush(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert_eq!(&framed.get_ref().written, b"outgoing\n");
    }

    #[test]
    fn framed_multiple_reads() {
        let transport = DuplexBuf::new(b"one\ntwo\nthree\n");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "one"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "two"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "three"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_close() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        framed.send("final".to_string()).unwrap();
        let poll = framed.poll_close(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert_eq!(&framed.get_ref().written, b"final\n");
    }

    #[test]
    fn framed_accessors() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());

        assert!(framed.read_buffer().is_empty());
        assert!(framed.write_buffer().is_empty());
        let _codec = framed.codec();
        let _codec_mut = framed.codec_mut();
        let _transport = framed.get_ref();
        let _transport_mut = framed.get_mut();
    }

    #[test]
    fn framed_into_parts() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::new(transport, LinesCodec::new());

        let parts = framed.into_parts();
        assert!(parts.read_buf.is_empty());
        assert!(parts.write_buf.is_empty());
    }

    // Pure data-type tests (wave 15 – CyanBarn)

    #[test]
    fn framed_debug() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::new(transport, LinesCodec::new());
        let dbg = format!("{framed:?}");
        assert!(dbg.contains("Framed"));
        assert!(dbg.contains("read_buf_len"));
        assert!(dbg.contains("write_buf_len"));
    }

    #[test]
    fn framed_with_capacity() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::with_capacity(transport, LinesCodec::new(), 256);
        // Buffers should have been allocated with the specified capacity.
        assert!(framed.read_buffer().is_empty());
        assert!(framed.write_buffer().is_empty());
    }

    #[test]
    fn framed_into_inner() {
        let transport = DuplexBuf::new(b"test-data");
        let framed = Framed::new(transport, LinesCodec::new());
        let inner = framed.into_inner();
        assert_eq!(&inner.read_data, b"test-data");
        assert_eq!(inner.read_pos, 0);
    }

    #[test]
    fn framed_parts_fields() {
        let transport = DuplexBuf::new(b"parts-test\n");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Read to populate the read buffer then extract parts.
        let _ = Pin::new(&mut framed).poll_next(&mut cx);
        let parts = framed.into_parts();
        // The inner transport and codec should be accessible.
        let inner = parts.inner;
        assert_eq!(&inner.read_data, b"parts-test\n");
        let _ = parts.codec;
    }

    #[test]
    fn framed_get_mut_modifies_transport() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        framed.get_mut().read_data = b"modified\n".to_vec();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "modified"));
    }

    #[test]
    fn framed_codec_mut_accessible() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        // Just verify codec_mut returns a mutable reference.
        let _codec = framed.codec_mut();
    }

    #[test]
    fn framed_empty_read_returns_none() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }
}
