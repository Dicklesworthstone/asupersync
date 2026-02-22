//! AsyncWrite trait and adapters.

use std::io::{self, IoSlice};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Async non-blocking write.
pub trait AsyncWrite {
    /// Attempt to write data from `buf`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>;

    /// Attempt to write data from multiple buffers (vectored I/O).
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // Default implementation: write first non-empty buffer
        for buf in bufs {
            if !buf.is_empty() {
                return self.poll_write(cx, buf);
            }
        }
        Poll::Ready(Ok(0))
    }

    /// Returns whether this writer has efficient vectored writes.
    fn is_write_vectored(&self) -> bool {
        false
    }

    /// Attempt to flush buffered data.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Attempt to shutdown the writer.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// Async non-blocking write from multiple buffers (vectored I/O).
pub trait AsyncWriteVectored: AsyncWrite {
    /// Attempt to write data from multiple buffers (vectored I/O).
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write_vectored(self, cx, bufs)
    }

    /// Returns whether this writer has efficient vectored writes.
    fn is_write_vectored(&self) -> bool {
        AsyncWrite::is_write_vectored(self)
    }
}

impl<W> AsyncWriteVectored for W where W: AsyncWrite + ?Sized {}

impl AsyncWrite for Vec<u8> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for std::io::Cursor<&mut [u8]> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write as _;

        let this = self.get_mut();
        let n = this.write(buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for std::io::Cursor<Vec<u8>> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write as _;

        let this = self.get_mut();
        let n = this.write(buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for std::io::Cursor<Box<[u8]>> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write as _;

        let this = self.get_mut();
        let n = this.write(buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl<W> AsyncWrite for &mut W
where
    W: AsyncWrite + Unpin + ?Sized,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_shutdown(cx)
    }
}

impl<W> AsyncWrite for Box<W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_shutdown(cx)
    }
}

impl<W, P> AsyncWrite for Pin<P>
where
    P: DerefMut<Target = W> + Unpin,
    W: AsyncWrite + ?Sized,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pin_project::pin_project;
    use std::marker::PhantomPinned;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

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
    fn write_to_vec() {
        init_test("write_to_vec");
        let mut output = Vec::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut output).poll_write(&mut cx, b"hello");
        let ready = matches!(poll, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ready, "write 5", true, ready);
        crate::assert_with_log!(output == b"hello", "output", b"hello", output);
        crate::test_complete!("write_to_vec");
    }

    #[test]
    fn write_to_cursor() {
        init_test("write_to_cursor");
        let mut buf = [0u8; 8];
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut cursor).poll_write(&mut cx, b"test");
        let ready = matches!(poll, Poll::Ready(Ok(4)));
        crate::assert_with_log!(ready, "write 4", true, ready);
        crate::assert_with_log!(&buf[..4] == b"test", "buf", b"test", &buf[..4]);
        crate::test_complete!("write_to_cursor");
    }

    #[test]
    fn flush_and_shutdown_vec() {
        init_test("flush_and_shutdown_vec");
        let mut output = Vec::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut output).poll_flush(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "flush ready", true, ready);

        let poll = Pin::new(&mut output).poll_shutdown(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "shutdown ready", true, ready);
        crate::test_complete!("flush_and_shutdown_vec");
    }

    #[test]
    fn write_via_ref() {
        init_test("write_via_ref");
        let mut output = Vec::new();
        let mut writer = &mut output;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut writer).poll_write(&mut cx, b"via ref");
        let ready = matches!(poll, Poll::Ready(Ok(7)));
        crate::assert_with_log!(ready, "write 7", true, ready);
        crate::assert_with_log!(output == b"via ref", "output", b"via ref", output);
        crate::test_complete!("write_via_ref");
    }

    #[test]
    fn write_via_box() {
        init_test("write_via_box");
        let mut output: Box<Vec<u8>> = Box::default();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut output).poll_write(&mut cx, b"boxed");
        let ready = matches!(poll, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ready, "write 5", true, ready);
        crate::assert_with_log!(*output == b"boxed", "output", b"boxed", *output);
        crate::test_complete!("write_via_box");
    }

    #[pin_project]
    struct PinnedWriter<W> {
        #[pin]
        inner: W,
        _pin: PhantomPinned,
    }

    impl<W> AsyncWrite for PinnedWriter<W>
    where
        W: AsyncWrite,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.project().inner.poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().inner.poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().inner.poll_shutdown(cx)
        }
    }

    #[test]
    fn pin_wrapper_write_supports_non_unpin_inner() {
        init_test("pin_wrapper_write_supports_non_unpin_inner");

        let mut writer = Box::pin(PinnedWriter {
            inner: Vec::<u8>::new(),
            _pin: PhantomPinned,
        });

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut writer).poll_write(&mut cx, b"ok");
        let ready = matches!(poll, Poll::Ready(Ok(2)));
        crate::assert_with_log!(ready, "write 2", true, ready);
        crate::assert_with_log!(
            writer.as_ref().get_ref().inner == b"ok",
            "inner output",
            b"ok",
            writer.as_ref().get_ref().inner
        );

        crate::test_complete!("pin_wrapper_write_supports_non_unpin_inner");
    }
}
