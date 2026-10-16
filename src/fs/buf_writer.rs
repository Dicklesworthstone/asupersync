//! Buffered async writer for filesystem I/O.
//!
//! This is a thin wrapper around the core `io::BufWriter` to provide
//! a convenient `fs`-scoped type for file operations.

use crate::io::{self, AsyncWrite};
use std::io::{self as std_io, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Buffered async file writer.
#[derive(Debug)]
pub struct BufWriter<W> {
    inner: io::BufWriter<W>,
}

impl<W> BufWriter<W> {
    /// Creates a new `BufWriter` with default capacity.
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner: io::BufWriter::new(inner),
        }
    }

    /// Creates a new `BufWriter` with specified capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize, inner: W) -> Self {
        Self {
            inner: io::BufWriter::with_capacity(capacity, inner),
        }
    }

    /// Gets a reference to the underlying writer.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        self.inner.get_ref()
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// Note: writing directly to the inner writer may cause data ordering issues
    /// if the buffer contains unflushed data.
    pub fn get_mut(&mut self) -> &mut W {
        self.inner.get_mut()
    }

    /// Returns the underlying writer.
    ///
    /// Note: any buffered data that has not been flushed will be lost.
    pub fn into_inner(self) -> W {
        self.inner.into_inner()
    }

    /// Returns buffered bytes not yet accepted by the underlying writer.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    /// Returns the capacity of the internal buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BufWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std_io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std_io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std_io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std_io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
#[path = "buf_writer_inline_tests.rs"]
mod tests;
