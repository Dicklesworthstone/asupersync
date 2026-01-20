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
//! separately (but not concurrently polled). For concurrent use, the halves
//! should be used in separate async tasks.

use super::{AsyncRead, AsyncWrite, ReadBuf};
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
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    /// A simple stream that supports both read and write.
    struct TestStream {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl TestStream {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_data: read_data.to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.read_pos >= this.read_data.len() {
                return Poll::Ready(Ok(()));
            }
            let to_copy = std::cmp::min(this.read_data.len() - this.read_pos, buf.remaining());
            buf.put_slice(&this.read_data[this.read_pos..this.read_pos + to_copy]);
            this.read_pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn split_stream_creates_halves() {
        init_test("split_stream_creates_halves");
        let stream = TestStream::new(b"hello");
        let wrapper = SplitStream::new(stream);
        let (read_half, write_half) = wrapper.split();

        // Verify the halves exist - use _ = to drop without triggering clippy
        let _ = read_half;
        let _ = write_half;

        // Access the underlying stream
        let inner = wrapper.get_ref();
        crate::assert_with_log!(inner.read_pos == 0, "read_pos", 0, inner.read_pos);
        let empty = inner.written.is_empty();
        crate::assert_with_log!(empty, "written empty", true, empty);
        crate::test_complete!("split_stream_creates_halves");
    }

    #[test]
    fn read_half_reads() {
        init_test("read_half_reads");
        let stream = TestStream::new(b"hello");
        let wrapper = SplitStream::new(stream);
        let (mut read_half, _write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 5];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut read_half).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hello", "filled", b"hello", filled);
        crate::test_complete!("read_half_reads");
    }

    #[test]
    fn write_half_writes() {
        init_test("write_half_writes");
        let stream = TestStream::new(b"");
        let wrapper = SplitStream::new(stream);
        let (_read_half, mut write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut write_half).poll_write(&mut cx, b"world");
        let ready = matches!(poll, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ready, "write 5", true, ready);

        // Check the underlying stream - use _ = to drop without triggering clippy
        let _ = write_half;
        let inner = wrapper.get_ref();
        crate::assert_with_log!(
            inner.written == b"world",
            "written",
            b"world",
            inner.written
        );
        crate::test_complete!("write_half_writes");
    }

    #[test]
    fn write_half_flush_and_shutdown() {
        init_test("write_half_flush_and_shutdown");
        let stream = TestStream::new(b"");
        let wrapper = SplitStream::new(stream);
        let (_read_half, mut write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut write_half).poll_flush(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "flush ready", true, ready);

        let poll = Pin::new(&mut write_half).poll_shutdown(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "shutdown ready", true, ready);
        crate::test_complete!("write_half_flush_and_shutdown");
    }

    #[test]
    fn into_inner_works() {
        init_test("into_inner_works");
        let stream = TestStream::new(b"test");
        let wrapper = SplitStream::new(stream);
        let stream = wrapper.into_inner();
        crate::assert_with_log!(
            stream.read_data == b"test",
            "read_data",
            b"test",
            stream.read_data
        );
        crate::test_complete!("into_inner_works");
    }
}
