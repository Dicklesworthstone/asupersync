//! Buffered async reader.
//!
//! This module provides [`BufReader`], a wrapper around an [`AsyncRead`] that
//! adds an internal buffer to reduce the number of read calls.
//!
//! # Cancel Safety
//!
//! - `poll_read` is cancel-safe. Partial reads are discarded by the caller.
//! - `poll_fill_buf` is cancel-safe. The buffer state is consistent.
//! - Line-read cancellation guarantees depend on the adapter: see
//!   [`super::LineReader`] and [`super::read_line`] for partial UTF-8 handling.

use super::{AsyncBufRead, AsyncRead, AsyncSeek, ReadBuf};
use std::io::{self, SeekFrom};
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
/// ```
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
    /// A substituted read buffer makes the source's progress unknowable.
    read_buffer_replaced: bool,
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
        let capacity = capacity.max(1);
        Self {
            inner,
            buf: vec![0u8; capacity].into_boxed_slice(),
            pos: 0,
            cap: 0,
            read_buffer_replaced: false,
        }
    }

    /// Returns a reference to the underlying reader.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the underlying reader.
    ///
    /// Note: Reading from or seeking the inner reader directly may cause data
    /// loss or make the buffered reader's logical position inconsistent if the
    /// buffer contains unread data.
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

impl<R: AsyncRead + Unpin> BufReader<R> {
    fn check_read_buffer(&self) -> io::Result<()> {
        if self.read_buffer_replaced {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffered reader replaced the read buffer it was given; endpoint effects are unknown",
            ))
        } else {
            Ok(())
        }
    }

    /// Retain every in-place fill before interpreting the provider's status.
    /// Both buffered entry points must use the same progress accounting.
    fn poll_refill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_read_buffer()?;
        self.pos = 0;
        self.cap = 0;
        let start = self.buf.as_ptr();
        let offered = self.buf.len();
        let mut read_buf = ReadBuf::new(&mut self.buf);
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut read_buf);
        if !super::transfer_session::filled_in_place(read_buf.filled(), start, offered) {
            self.read_buffer_replaced = true;
            return Poll::Ready(self.check_read_buffer());
        }
        self.cap = read_buf.filled().len();
        match result {
            // Return the original error, but keep any bytes already consumed
            // from the source available through buffer() or the next read.
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending if self.cap == 0 => Poll::Pending,
            Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BufReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        this.check_read_buffer()?;

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
        match this.poll_refill(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
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
        this.check_read_buffer()?;

        // If buffer is empty, fill it
        if this.pos >= this.cap {
            match this.poll_refill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }

        Poll::Ready(Ok(&this.buf[this.pos..this.cap]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        this.pos = this.pos.saturating_add(amt).min(this.cap);
    }
}

impl<R: AsyncSeek + Unpin> AsyncSeek for BufReader<R> {
    /// Seeks the underlying reader while accounting for unread buffered bytes.
    ///
    /// `SeekFrom::Current` is relative to this reader's logical position, not
    /// the underlying reader's physical position after read-ahead. A successful
    /// seek discards the buffer. `Pending` and errors preserve it unless the
    /// signed-underflow fallback has already completed its first physical seek.
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        let result = if let SeekFrom::Current(offset) = pos {
            let unread = match i64::try_from(this.cap - this.pos) {
                Ok(unread) => unread,
                Err(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "buffered seek distance exceeds i64",
                    )));
                }
            };

            if let Some(adjusted) = offset.checked_sub(unread) {
                match Pin::new(&mut this.inner).poll_seek(cx, SeekFrom::Current(adjusted)) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(position)) => position,
                }
            } else {
                // Rewind the read-ahead separately so subtracting it cannot
                // overflow. Once this succeeds the old buffer is invalid even
                // if the requested seek later returns Pending or an error.
                match Pin::new(&mut this.inner).poll_seek(cx, SeekFrom::Current(-unread)) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(_)) => this.discard_buffer(),
                }
                match Pin::new(&mut this.inner).poll_seek(cx, SeekFrom::Current(offset)) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(position)) => position,
                }
            }
        } else {
            match Pin::new(&mut this.inner).poll_seek(cx, pos) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(position)) => position,
            }
        };

        this.discard_buffer();
        Poll::Ready(Ok(result))
    }
}

#[cfg(test)]
#[path = "buf_reader_inline_tests.rs"]
mod tests;
