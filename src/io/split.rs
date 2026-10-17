//! Split a combined read/write stream into separate halves.
//!
//! This module provides the [`split`] function to split a type that implements
//! both [`AsyncRead`] and [`AsyncWrite`] into separate reader and writer halves.
//!
//! # Cancel Safety
//!
//! The split operation is purely structural and has no cancel safety concerns.
//! The resulting halves inherit the cancel safety properties of the underlying
//! stream's read and write operations.
//!
//! # Usage Pattern
//!
//! This module provides a borrowing split that returns halves which can be used
//! separately (but not concurrently polled). Because they borrow from the local
//! scope and use `RefCell` (making them `!Send`), they **cannot** be spawned into
//! separate async tasks. For concurrent use across tasks, use an owned split
//! provided by the underlying stream (e.g., `TcpStream::into_split()`).

use super::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use std::cell::RefCell;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A wrapper around a stream that allows splitting into read/write halves.
///
/// This wrapper uses `RefCell` for interior mutability, allowing the halves
/// to share access to the underlying stream safely.
///
/// # Panics
///
/// Will panic if both halves try to access the stream simultaneously
/// within the same thread.
pub struct SplitStream<T> {
    inner: RefCell<T>,
}

impl<T> SplitStream<T> {
    /// Creates a new split stream wrapper.
    #[must_use]
    pub fn new(stream: T) -> Self {
        Self {
            inner: RefCell::new(stream),
        }
    }

    /// Splits this wrapper into read and write halves.
    #[must_use]
    pub fn split(&self) -> (ReadHalf<'_, T>, WriteHalf<'_, T>)
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        (
            ReadHalf { inner: &self.inner },
            WriteHalf { inner: &self.inner },
        )
    }

    /// Returns a reference to the underlying stream.
    ///
    /// # Panics
    ///
    /// Panics if the stream is currently borrowed.
    pub fn get_ref(&self) -> std::cell::Ref<'_, T> {
        self.inner.borrow()
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Panics
    ///
    /// Panics if the stream is currently borrowed.
    pub fn get_mut(&self) -> std::cell::RefMut<'_, T> {
        self.inner.borrow_mut()
    }

    /// Consumes this wrapper, returning the inner stream.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

/// Convenience function to split a stream into read and write halves.
///
/// This creates a `SplitStream` wrapper and splits it. Note that the
/// wrapper must be kept alive for as long as the halves are in use.
///
/// For a simpler API, prefer creating a `SplitStream` directly:
///
/// ```ignore
/// let wrapper = SplitStream::new(stream);
/// let (read_half, write_half) = wrapper.split();
/// ```
pub fn split<T>(wrapper: &SplitStream<T>) -> (ReadHalf<'_, T>, WriteHalf<'_, T>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    wrapper.split()
}

/// The read half of a split stream.
///
/// Created by [`SplitStream::split`]. Implements [`AsyncRead`].
#[derive(Debug)]
pub struct ReadHalf<'a, T> {
    inner: &'a RefCell<T>,
}

impl<T> AsyncRead for ReadHalf<'_, T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner.borrow_mut();
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl<T> AsyncReadVectored for ReadHalf<'_, T>
where
    T: AsyncReadVectored + Unpin,
{
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.borrow_mut();
        Pin::new(&mut *inner).poll_read_vectored(cx, bufs)
    }
}

/// The write half of a split stream.
///
/// Created by [`SplitStream::split`]. Implements [`AsyncWrite`].
#[derive(Debug)]
pub struct WriteHalf<'a, T> {
    inner: &'a RefCell<T>,
}

impl<T> AsyncWrite for WriteHalf<'_, T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.borrow_mut();
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.borrow_mut();
        Pin::new(&mut *inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        let inner = self.inner.borrow();
        inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.borrow_mut();
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.borrow_mut();
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "split_inline_tests.rs"]
mod tests;
