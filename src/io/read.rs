//! AsyncRead trait and adapters.

use super::ReadBuf;
use std::io;
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

    #[test]
    fn read_from_slice_advances() {
        let mut input: &[u8] = b"hello";
        let mut buf = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut input).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"he");
        assert_eq!(input, b"llo");
    }

    #[test]
    fn chain_reads_both() {
        let first: &[u8] = b"hi";
        let second: &[u8] = b"there";
        let mut chain = Chain::new(first, second);
        let mut buf = [0u8; 7];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hi");

        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hithere");
    }

    #[test]
    fn take_limits_reads() {
        let input: &[u8] = b"abcdef";
        let mut take = Take::new(input, 3);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut take).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"abc");
        assert_eq!(take.limit(), 0);
    }
}
