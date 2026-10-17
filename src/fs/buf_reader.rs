//! Buffered async reader for filesystem I/O.
//!
//! This is a thin wrapper around the core `io::BufReader` to provide
//! a convenient `fs`-scoped type for file operations.

use crate::fs::Lines;
use crate::io::{self, AsyncBufRead, AsyncRead, AsyncSeek, ReadBuf};
use std::io::{Result, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Buffered async reader.
#[derive(Debug)]
pub struct BufReader<R> {
    inner: io::BufReader<R>,
}

impl<R> BufReader<R> {
    /// Creates a new `BufReader` with the default buffer capacity.
    pub fn new(inner: R) -> Self {
        Self {
            inner: io::BufReader::new(inner),
        }
    }

    /// Creates a new `BufReader` with the specified buffer capacity.
    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner: io::BufReader::with_capacity(capacity, inner),
        }
    }

    /// Returns a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the underlying reader.
    ///
    /// Note: reading from or seeking the inner reader directly may cause data
    /// loss or make the buffered reader's logical position inconsistent if the
    /// buffer contains unread data.
    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut()
    }

    /// Consumes the `BufReader` and returns the underlying reader.
    ///
    /// Note: any buffered data that has not been read will be lost.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }

    /// Returns the current buffer contents.
    pub fn buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    /// Returns the capacity of the internal buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns an iterator over the lines of this reader.
    pub fn lines(self) -> Lines<R> {
        Lines {
            inner: crate::io::Lines::new(self),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BufReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for BufReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<&[u8]>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        Pin::new(&mut this.inner).consume(amt);
    }
}

impl<R: AsyncSeek + Unpin> AsyncSeek for BufReader<R> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<Result<u64>> {
        Pin::new(&mut self.inner).poll_seek(cx, pos)
    }
}

#[cfg(test)]
#[path = "buf_reader_inline_tests.rs"]
mod tests;
