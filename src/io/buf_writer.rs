//! Buffered async writer.
//!
//! This module provides [`BufWriter`], a wrapper around an [`AsyncWrite`] that
//! adds an internal buffer to reduce the number of write calls.
//!
//! # Cancel Safety
//!
//! - `poll_write` is cancel-safe. Partial writes are tracked consistently.
//! - `poll_flush` is cancel-safe. Can be retried if cancelled.
//! - `poll_shutdown` is cancel-safe. Flushes then shuts down.
//!
//! **Important:** Data in the buffer may be lost if the `BufWriter` is dropped
//! without calling `flush` or `shutdown`.

use super::AsyncWrite;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer capacity for [`BufWriter`].
const DEFAULT_BUF_CAPACITY: usize = 8192;

/// Async buffered writer.
///
/// Wraps an [`AsyncWrite`] and provides buffering for more efficient writes.
/// Uses an internal buffer to reduce the number of underlying write calls.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::BufWriter;
///
/// let writer = Vec::new();
/// let mut buf_writer = BufWriter::new(writer);
///
/// // Write to the buffered writer
/// // Data is batched and written when buffer fills or flush is called
/// ```
///
/// # Flushing
///
/// Data is not written to the underlying writer until:
/// - The internal buffer is full
/// - `flush()` is called
/// - `shutdown()` is called
/// - A write exceeds the buffer capacity
///
/// Always ensure you flush or shutdown the writer to avoid data loss.
#[derive(Debug)]
pub struct BufWriter<W> {
    inner: W,
    buf: Vec<u8>,
    capacity: usize,
    /// Number of bytes written from buf during a flush operation.
    /// Used to track partial flush progress.
    written: usize,
}

impl<W> BufWriter<W> {
    /// Creates a new `BufWriter` with the default buffer capacity (8192 bytes).
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self::with_capacity(DEFAULT_BUF_CAPACITY, inner)
    }

    /// Creates a new `BufWriter` with the specified buffer capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize, inner: W) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(capacity),
            capacity,
            written: 0,
        }
    }

    /// Returns a reference to the underlying writer.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the underlying writer.
    ///
    /// Note: Writing directly to the inner writer may cause data ordering issues
    /// if the buffer contains unflushed data.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consumes the `BufWriter` and returns the underlying writer.
    ///
    /// **Warning:** Any buffered data that has not been flushed will be lost.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns the current buffer contents.
    ///
    /// This is the data that has been written to the `BufWriter`
    /// but has not yet been flushed to the underlying writer.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the capacity of the internal buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<W: AsyncWrite + Unpin> BufWriter<W> {
    /// Flushes the internal buffer, writing all data to the underlying writer.
    ///
    /// This is a helper method to drive the flush to completion.
    fn poll_flush_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.buf[self.written..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => {
                    self.written += n;
                }
            }
        }

        // Buffer fully written, clear it
        self.buf.clear();
        self.written = 0;

        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BufWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // If we have buffered data being flushed, continue the flush
        if this.written > 0 {
            match this.poll_flush_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }

        // If the data fits in the buffer, just append it
        if this.buf.len() + buf.len() <= this.capacity {
            this.buf.extend_from_slice(buf);
            return Poll::Ready(Ok(buf.len()));
        }

        // If buffer is not empty, flush it first
        if !this.buf.is_empty() {
            match this.poll_flush_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }

        // If the data is larger than our buffer, write directly
        if buf.len() >= this.capacity {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // Otherwise, buffer the data
        this.buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Calculate total length
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();

        // If we have buffered data being flushed, continue the flush
        if this.written > 0 {
            match this.poll_flush_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }

        // If all data fits in the buffer, just append it
        if this.buf.len() + total_len <= this.capacity {
            for buf in bufs {
                this.buf.extend_from_slice(buf);
            }
            return Poll::Ready(Ok(total_len));
        }

        // If buffer is not empty, flush it first
        if !this.buf.is_empty() {
            match this.poll_flush_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }

        // If total is larger than capacity, write directly using vectored I/O
        if total_len >= this.capacity {
            return Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        }

        // Otherwise, buffer all the data
        for buf in bufs {
            this.buf.extend_from_slice(buf);
        }
        Poll::Ready(Ok(total_len))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Flush our internal buffer
        match this.poll_flush_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        // Flush the underlying writer
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Flush our internal buffer first
        match this.poll_flush_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        // Shutdown the underlying writer
        Pin::new(&mut this.inner).poll_shutdown(cx)
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn buf_writer_new() {
        init_test("buf_writer_new");
        let writer: Vec<u8> = Vec::new();
        let buf_writer = BufWriter::new(writer);
        let capacity = buf_writer.capacity();
        crate::assert_with_log!(
            capacity == DEFAULT_BUF_CAPACITY,
            "capacity",
            DEFAULT_BUF_CAPACITY,
            capacity
        );
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_writer_new");
    }

    #[test]
    fn buf_writer_with_capacity() {
        init_test("buf_writer_with_capacity");
        let writer: Vec<u8> = Vec::new();
        let buf_writer = BufWriter::with_capacity(256, writer);
        let capacity = buf_writer.capacity();
        crate::assert_with_log!(capacity == 256, "capacity", 256, capacity);
        crate::test_complete!("buf_writer_with_capacity");
    }

    #[test]
    fn buf_writer_get_ref() {
        init_test("buf_writer_get_ref");
        let writer = vec![42];
        let buf_writer = BufWriter::new(writer);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == &[42], "get_ref", &[42], inner);
        crate::test_complete!("buf_writer_get_ref");
    }

    #[test]
    fn buf_writer_into_inner() {
        init_test("buf_writer_into_inner");
        let writer = vec![42];
        let buf_writer = BufWriter::new(writer);
        let inner = buf_writer.into_inner();
        crate::assert_with_log!(inner == vec![42], "into_inner", vec![42], inner);
        crate::test_complete!("buf_writer_into_inner");
    }

    #[test]
    fn buf_writer_small_write_buffered() {
        init_test("buf_writer_small_write_buffered");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(16, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write small data - should be buffered
        let poll = Pin::new(&mut buf_writer).poll_write(&mut cx, b"hello");
        let ready = matches!(poll, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ready, "write 5", true, ready);

        // Data should be in buffer, not in inner writer
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"hello", "buffer", b"hello", buffer);
        let inner_empty = buf_writer.get_ref().is_empty();
        crate::assert_with_log!(inner_empty, "inner empty", true, inner_empty);
        crate::test_complete!("buf_writer_small_write_buffered");
    }

    #[test]
    fn buf_writer_flush_writes_to_inner() {
        init_test("buf_writer_flush_writes_to_inner");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(16, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"hello");
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(!empty, "buffer not empty", false, empty);

        // Flush
        let poll = Pin::new(&mut buf_writer).poll_flush(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "flush ready", true, ready);

        // Buffer should be empty, data in inner
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"hello", "inner", b"hello", inner);
        crate::test_complete!("buf_writer_flush_writes_to_inner");
    }

    #[test]
    fn buf_writer_buffer_full_auto_flush() {
        init_test("buf_writer_buffer_full_auto_flush");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data that fills buffer
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"12345678");
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"12345678", "buffer", b"12345678", buffer);
        let inner_empty = buf_writer.get_ref().is_empty();
        crate::assert_with_log!(inner_empty, "inner empty", true, inner_empty);

        // Write more data - should trigger flush
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"9ABC");

        // First buffer should have been flushed
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"12345678", "inner", b"12345678", inner);
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"9ABC", "buffer", b"9ABC", buffer);
        crate::test_complete!("buf_writer_buffer_full_auto_flush");
    }

    #[test]
    fn buf_writer_large_write_bypasses_buffer() {
        init_test("buf_writer_large_write_bypasses_buffer");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data larger than buffer capacity
        let poll = Pin::new(&mut buf_writer).poll_write(&mut cx, b"this is large data");
        let ready = matches!(poll, Poll::Ready(Ok(18)));
        crate::assert_with_log!(ready, "write 18", true, ready);

        // Data should go directly to inner writer
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(
            inner == b"this is large data",
            "inner",
            b"this is large data",
            inner
        );
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_writer_large_write_bypasses_buffer");
    }

    #[test]
    fn buf_writer_multiple_writes() {
        init_test("buf_writer_multiple_writes");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(32, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Multiple small writes
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"hello ");
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"world");
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"hello world", "buffer", b"hello world", buffer);
        let inner_empty = buf_writer.get_ref().is_empty();
        crate::assert_with_log!(inner_empty, "inner empty", true, inner_empty);

        // Flush
        let _ = Pin::new(&mut buf_writer).poll_flush(&mut cx);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"hello world", "inner", b"hello world", inner);
        crate::test_complete!("buf_writer_multiple_writes");
    }

    #[test]
    fn buf_writer_shutdown_flushes() {
        init_test("buf_writer_shutdown_flushes");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(32, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"pending data");

        // Shutdown should flush
        let poll = Pin::new(&mut buf_writer).poll_shutdown(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "shutdown ready", true, ready);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"pending data", "inner", b"pending data", inner);
        crate::test_complete!("buf_writer_shutdown_flushes");
    }

    #[test]
    fn buf_writer_vectored_write_buffered() {
        init_test("buf_writer_vectored_write_buffered");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(32, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let bufs = [IoSlice::new(b"hello "), IoSlice::new(b"world")];
        let poll = Pin::new(&mut buf_writer).poll_write_vectored(&mut cx, &bufs);
        let ready = matches!(poll, Poll::Ready(Ok(11)));
        crate::assert_with_log!(ready, "write 11", true, ready);
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"hello world", "buffer", b"hello world", buffer);
        crate::test_complete!("buf_writer_vectored_write_buffered");
    }

    #[test]
    fn buf_writer_vectored_write_large_direct() {
        init_test("buf_writer_vectored_write_large_direct");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let bufs = [IoSlice::new(b"this is "), IoSlice::new(b"large data")];
        let poll = Pin::new(&mut buf_writer).poll_write_vectored(&mut cx, &bufs);
        let ready = matches!(poll, Poll::Ready(Ok(_)));
        crate::assert_with_log!(ready, "write ready", true, ready);

        // Should write directly to inner (bypassing buffer)
        // Note: The exact behavior depends on the underlying writer's vectored support
        crate::test_complete!("buf_writer_vectored_write_large_direct");
    }

    #[test]
    fn buf_writer_empty_write() {
        init_test("buf_writer_empty_write");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::new(writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut buf_writer).poll_write(&mut cx, b"");
        let ready = matches!(poll, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ready, "write 0", true, ready);
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_writer_empty_write");
    }
}
