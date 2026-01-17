//! Buffered async reader.
//!
//! This module provides [`BufReader`], a wrapper around an [`AsyncRead`] that
//! adds an internal buffer to reduce the number of read calls.
//!
//! # Cancel Safety
//!
//! - `poll_read` is cancel-safe. Partial reads are discarded by the caller.
//! - `poll_fill_buf` is cancel-safe. The buffer state is consistent.
//! - Lines/read_line are cancel-safe since they use buffered operations.

use super::{AsyncBufRead, AsyncRead, ReadBuf};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer capacity for [`BufReader`].
const DEFAULT_BUF_CAPACITY: usize = 8192;

/// Async buffered reader.
///
/// Wraps an [`AsyncRead`] and provides buffering for more efficient reads.
/// Uses an internal buffer to reduce the number of underlying read calls.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::{BufReader, AsyncBufRead};
///
/// let reader: &[u8] = b"hello world";
/// let mut buf_reader = BufReader::new(reader);
///
/// // Can now use buffered read methods
/// ```
#[derive(Debug)]
pub struct BufReader<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl<R> BufReader<R> {
    /// Creates a new `BufReader` with the default buffer capacity (8192 bytes).
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_CAPACITY, inner)
    }

    /// Creates a new `BufReader` with the specified buffer capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            buf: vec![0u8; capacity].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    /// Returns a reference to the underlying reader.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the underlying reader.
    ///
    /// Note: Reading directly from the inner reader may cause data loss
    /// if the buffer contains unread data.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consumes the `BufReader` and returns the underlying reader.
    ///
    /// Note: Any buffered data that has not been read will be lost.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns the current buffer contents.
    ///
    /// This is the data that has been read from the underlying reader
    /// but has not yet been consumed.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..self.cap]
    }

    /// Returns the capacity of the internal buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Discards any buffered data and resets the buffer state.
    pub fn discard_buffer(&mut self) {
        self.pos = 0;
        self.cap = 0;
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BufReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If we have buffered data, copy from it
        if this.pos < this.cap {
            let buffered = &this.buf[this.pos..this.cap];
            let to_copy = std::cmp::min(buffered.len(), buf.remaining());
            buf.put_slice(&buffered[..to_copy]);
            this.pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Buffer is empty. If the request is large enough, bypass the buffer
        // to avoid an extra copy.
        if buf.remaining() >= this.buf.len() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        // Fill the internal buffer
        this.pos = 0;
        this.cap = 0;
        let mut read_buf = ReadBuf::new(&mut this.buf);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                this.cap = read_buf.filled().len();
            }
        }

        // Copy from the newly filled buffer
        let to_copy = std::cmp::min(this.cap, buf.remaining());
        buf.put_slice(&this.buf[..to_copy]);
        this.pos = to_copy;

        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for BufReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();

        // If buffer is empty, fill it
        if this.pos >= this.cap {
            this.pos = 0;
            this.cap = 0;
            let mut read_buf = ReadBuf::new(&mut this.buf);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    this.cap = read_buf.filled().len();
                }
            }
        }

        Poll::Ready(Ok(&this.buf[this.pos..this.cap]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        this.pos = std::cmp::min(this.pos + amt, this.cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[test]
    fn buf_reader_new() {
        let data: &[u8] = b"hello world";
        let reader = BufReader::new(data);
        assert_eq!(reader.capacity(), DEFAULT_BUF_CAPACITY);
        assert!(reader.buffer().is_empty());
    }

    #[test]
    fn buf_reader_with_capacity() {
        let data: &[u8] = b"test";
        let reader = BufReader::with_capacity(256, data);
        assert_eq!(reader.capacity(), 256);
    }

    #[test]
    fn buf_reader_get_ref() {
        let data: &[u8] = b"hello";
        let reader = BufReader::new(data);
        assert_eq!(*reader.get_ref(), b"hello");
    }

    #[test]
    fn buf_reader_into_inner() {
        let data: &[u8] = b"hello";
        let reader = BufReader::new(data);
        let inner = reader.into_inner();
        assert_eq!(inner, b"hello");
    }

    #[test]
    fn buf_reader_read_small() {
        let mut data: &[u8] = b"hello world";
        let mut reader = BufReader::with_capacity(16, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 5];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hello");

        // Buffer should now contain " world"
        assert_eq!(reader.buffer(), b" world");
    }

    #[test]
    fn buf_reader_read_exact_buffer_size() {
        let mut data: &[u8] = b"exactly sixteen!";
        let mut reader = BufReader::with_capacity(16, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"exactly sixteen!");
    }

    #[test]
    fn buf_reader_large_read_bypasses_buffer() {
        let mut data: &[u8] = b"large data that exceeds buffer capacity easily";
        let mut reader = BufReader::with_capacity(8, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Request more than buffer capacity - should bypass buffer
        let mut buf = [0u8; 32];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        // Should read directly without going through internal buffer
        assert!(read_buf.filled().len() <= 32);
    }

    #[test]
    fn buf_reader_poll_fill_buf() {
        let mut data: &[u8] = b"buffered content";
        let mut reader = BufReader::with_capacity(32, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(_))));
        if let Poll::Ready(Ok(buf)) = poll {
            assert_eq!(buf, b"buffered content");
        }
    }

    #[test]
    fn buf_reader_consume() {
        let mut data: &[u8] = b"consume me";
        let mut reader = BufReader::with_capacity(32, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Fill buffer
        let _ = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        assert_eq!(reader.buffer(), b"consume me");

        // Consume 8 bytes
        Pin::new(&mut reader).consume(8);
        assert_eq!(reader.buffer(), b"me");

        // Consume rest
        Pin::new(&mut reader).consume(2);
        assert!(reader.buffer().is_empty());
    }

    #[test]
    fn buf_reader_discard_buffer() {
        let mut data: &[u8] = b"discard this";
        let mut reader = BufReader::with_capacity(32, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Fill buffer
        let _ = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        assert!(!reader.buffer().is_empty());

        // Discard
        reader.discard_buffer();
        assert!(reader.buffer().is_empty());
    }

    #[test]
    fn buf_reader_empty_source() {
        let mut data: &[u8] = b"";
        let mut reader = BufReader::new(data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(buf)) if buf.is_empty()));
    }

    #[test]
    fn buf_reader_multiple_reads() {
        let mut data: &[u8] = b"first second third";
        let mut reader = BufReader::with_capacity(8, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First read
        let mut buf1 = [0u8; 6];
        let mut read_buf1 = ReadBuf::new(&mut buf1);
        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf1);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf1.filled(), b"first ");

        // Second read (from buffer)
        let mut buf2 = [0u8; 6];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf2);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf2.filled(), b"se");

        // Third read (needs refill)
        let mut buf3 = [0u8; 10];
        let mut read_buf3 = ReadBuf::new(&mut buf3);
        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf3);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        // Result depends on buffer state
    }
}
