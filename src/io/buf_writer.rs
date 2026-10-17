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
    /// A prefix accepted during a partial flush is excluded, even if the
    /// flush subsequently returned `Pending` or an error.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buf[self.written..]
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
            let remaining = self.buf.len() - self.written;
            match Pin::new(&mut self.inner).poll_write(cx, &self.buf[self.written..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(n)) if n > remaining => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("writer reported {n} bytes written for {remaining}-byte buffer"),
                    )));
                }
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
        true
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
#[path = "buf_writer_inline_tests.rs"]
mod tests;
