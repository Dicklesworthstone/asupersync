//! AsyncRead trait and adapters.

use super::ReadBuf;
use std::io::{self, IoSliceMut};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Async non-blocking read.
pub trait AsyncRead {
    /// Attempt to read data into `buf`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
}

/// Async non-blocking read into multiple buffers (vectored I/O).
pub trait AsyncReadVectored: AsyncRead {
    /// Attempt to read data into multiple buffers.
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut this = self;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }

            let mut read_buf = ReadBuf::new(buf);
            return match AsyncRead::poll_read(this.as_mut(), cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            };
        }

        Poll::Ready(Ok(0))
    }
}

/// Chain two readers.
#[derive(Debug)]
pub struct Chain<R1, R2> {
    first: R1,
    second: R2,
    done_first: bool,
}

impl<R1, R2> Chain<R1, R2> {
    /// Creates a new `Chain` adapter.
    #[must_use]
    pub fn new(first: R1, second: R2) -> Self {
        Self {
            first,
            second,
            done_first: false,
        }
    }
}

impl<R1, R2> AsyncRead for Chain<R1, R2>
where
    R1: AsyncRead + Unpin,
    R2: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.done_first {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let before = buf.filled().len();
            match Pin::new(&mut this.first).poll_read(cx, buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == before {
                        this.done_first = true;
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        Pin::new(&mut this.second).poll_read(cx, buf)
    }
}

/// Take at most `limit` bytes from a reader.
#[derive(Debug)]
pub struct Take<R> {
    inner: R,
    limit: u64,
}

impl<R> Take<R> {
    /// Creates a new `Take` adapter.
    #[must_use]
    pub fn new(inner: R, limit: u64) -> Self {
        Self { inner, limit }
    }

    /// Returns the remaining limit.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }
}

impl<R> AsyncRead for Take<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.limit == 0 {
            return Poll::Ready(Ok(()));
        }

        let max = std::cmp::min(buf.remaining() as u64, this.limit) as usize;
        if max == 0 {
            return Poll::Ready(Ok(()));
        }

        let filled_before = buf.filled().len();
        {
            let unfilled = &mut buf.unfilled()[..max];
            let mut limited = ReadBuf::new(unfilled);
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = limited.filled().len();
                    buf.advance(n);
                }
            }
        }
        let read = buf.filled().len().saturating_sub(filled_before);
        this.limit = this.limit.saturating_sub(read as u64);

        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for &[u8] {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_copy = std::cmp::min(this.len(), buf.remaining());
        buf.put_slice(&this[..to_copy]);
        *this = &this[to_copy..];

        Poll::Ready(Ok(()))
    }
}

impl<T> AsyncRead for std::io::Cursor<T>
where
    T: AsRef<[u8]> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read as _;

        let this = self.get_mut();
        let n = this.read(buf.unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl<R> AsyncRead for &mut R
where
    R: AsyncRead + Unpin + ?Sized,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read(cx, buf)
    }
}

impl<R> AsyncRead for Box<R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read(cx, buf)
    }
}

impl<R, P> AsyncRead for Pin<P>
where
    P: DerefMut<Target = R> + Unpin,
    R: AsyncRead + ?Sized,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_read(cx, buf)
    }
}

impl<R1, R2> AsyncReadVectored for Chain<R1, R2>
where
    R1: AsyncRead + Unpin,
    R2: AsyncRead + Unpin,
{
}

impl<R> AsyncReadVectored for Take<R> where R: AsyncRead + Unpin {}

impl AsyncReadVectored for &[u8] {}

impl<T> AsyncReadVectored for std::io::Cursor<T> where T: AsRef<[u8]> + Unpin {}

impl<R> AsyncReadVectored for &mut R where R: AsyncReadVectored + Unpin + ?Sized {}

impl<R> AsyncReadVectored for Box<R> where R: AsyncReadVectored + Unpin + ?Sized {}

impl<R, P> AsyncReadVectored for Pin<P>
where
    P: DerefMut<Target = R> + Unpin,
    R: AsyncReadVectored + ?Sized,
{
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
    fn read_from_slice_advances() {
        init_test("read_from_slice_advances");
        let mut input: &[u8] = b"hello";
        let mut buf = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut input).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"he", "filled", b"he", filled);
        crate::assert_with_log!(input == b"llo", "remaining", b"llo", input);
        crate::test_complete!("read_from_slice_advances");
    }

    #[test]
    fn chain_reads_both() {
        init_test("chain_reads_both");
        let first: &[u8] = b"hi";
        let second: &[u8] = b"there";
        let mut chain = Chain::new(first, second);
        let mut buf = [0u8; 7];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready first", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hi", "filled first", b"hi", filled);

        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready second", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hithere", "filled second", b"hithere", filled);
        crate::test_complete!("chain_reads_both");
    }

    #[test]
    fn chain_does_not_switch_on_full_buffer() {
        init_test("chain_does_not_switch_on_full_buffer");
        let first: &[u8] = b"A";
        let second: &[u8] = b"B";
        let mut chain = Chain::new(first, second);
        let mut buf = [0u8; 0]; // Full buffer (0 capacity)
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Read with full buffer - should return Ok(0) but NOT switch
        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 1", true, ready);

        // Internal state check: relies on implementation details or observable behavior
        // Since we can't inspect `done_first`, we check the next read behavior.

        // Read with capacity - should get "A"
        let mut buf2 = [0u8; 1];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf2);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 2", true, ready);
        let filled = read_buf2.filled();

        // If bug exists, it switched to "B" because it thought "A" was done
        crate::assert_with_log!(filled == b"A", "filled", b"A", filled);

        crate::test_complete!("chain_does_not_switch_on_full_buffer");
    }

    #[pin_project]
    struct PinnedReader<R> {
        #[pin]
        inner: R,
        _pin: PhantomPinned,
    }

    impl<R> AsyncRead for PinnedReader<R>
    where
        R: AsyncRead,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.project().inner.poll_read(cx, buf)
        }
    }

    #[test]
    fn pin_wrapper_read_supports_non_unpin_inner() {
        init_test("pin_wrapper_read_supports_non_unpin_inner");

        let inner: &[u8] = b"ok";
        let mut reader = Box::pin(PinnedReader {
            inner,
            _pin: PhantomPinned,
        });

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"ok", "filled", b"ok", filled);

        crate::test_complete!("pin_wrapper_read_supports_non_unpin_inner");
    }
}
