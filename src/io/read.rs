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

            let start = buf.as_ptr();
            let offered = buf.len();
            let mut read_buf = ReadBuf::new(buf);
            let result = AsyncRead::poll_read(this.as_mut(), cx, &mut read_buf);
            let filled = read_buf.filled();
            if !super::transfer_session::filled_in_place(filled, start, offered) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "scalar reader replaced the vectored destination buffer",
                )));
            }
            return match result {
                Poll::Pending if filled.is_empty() => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(filled.len())),
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
    #[inline]
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
    #[inline]
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
///
/// In-place progress is charged even if the provider returns `Pending` or an
/// error. A positive pending fill is returned as ready data; a provider error
/// is preserved alongside any progress visible in the caller's `ReadBuf`.
/// A provider panic or nonempty fill outside the offered storage makes further
/// nonempty reads fail with `InvalidData`: unknown input cannot be read twice.
#[derive(Debug)]
pub struct Take<R> {
    inner: R,
    limit: u64,
    poisoned: bool,
}

impl<R> Take<R> {
    /// Creates a new `Take` adapter.
    #[inline]
    #[must_use]
    pub fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            poisoned: false,
        }
    }

    /// Returns the remaining limit.
    #[inline]
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    fn check_read_state(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded reader has unknown provider effects; further reads are refused",
            ))
        } else {
            Ok(())
        }
    }
}

impl<R> AsyncRead for Take<R>
where
    R: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.check_read_state()?;
        if this.limit == 0 {
            return Poll::Ready(Ok(()));
        }

        let max = buf
            .remaining()
            .min(usize::try_from(this.limit).unwrap_or(usize::MAX));
        // Arm before calling user code; unwinding must not silently readmit
        // a provider whose source position may have changed without a count.
        this.poisoned = true;
        let (result, read) = {
            let unfilled = &mut buf.unfilled()[..max];
            let start = unfilled.as_ptr();
            let mut limited = ReadBuf::new(unfilled);
            let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
            if !super::transfer_session::filled_in_place(limited.filled(), start, max) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bounded reader replaced its limited destination buffer",
                )));
            }
            (result, limited.filled().len())
        };
        // These updates precede every return, including errors. The provider
        // has already consumed this prefix and it must not receive fresh quota.
        buf.advance(read);
        this.limit -= read as u64;
        this.poisoned = false;

        match result {
            Poll::Pending if read != 0 => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

impl AsyncRead for &[u8] {
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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

impl<R> AsyncReadVectored for &mut R
where
    R: AsyncReadVectored + Unpin + ?Sized,
{
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read_vectored(cx, bufs)
    }
}

impl<R> AsyncReadVectored for Box<R>
where
    R: AsyncReadVectored + Unpin + ?Sized,
{
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read_vectored(cx, bufs)
    }
}

impl<R, P> AsyncReadVectored for Pin<P>
where
    P: DerefMut<Target = R> + Unpin,
    R: AsyncReadVectored + ?Sized,
{
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_read_vectored(cx, bufs)
    }
}

#[cfg(test)]
#[path = "read_inline_tests.rs"]
mod tests;
