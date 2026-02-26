//! AsyncWrite extension methods.

use crate::io::AsyncWrite;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Minimal buffer trait for write_all_buf.
pub trait Buf {
    /// Returns the number of remaining bytes.
    fn remaining(&self) -> usize;
    /// Returns the current chunk of bytes.
    fn chunk(&self) -> &[u8];
    /// Advances the buffer by `cnt` bytes.
    fn advance(&mut self, cnt: usize);
}

impl Buf for &[u8] {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn chunk(&self) -> &[u8] {
        self
    }

    fn advance(&mut self, cnt: usize) {
        *self = &self[cnt..];
    }
}

/// Extension trait for `AsyncWrite`.
pub trait AsyncWriteExt: AsyncWrite {
    /// Write all bytes from `buf`.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> WriteAll<'a, Self>
    where
        Self: Unpin,
    {
        WriteAll {
            writer: self,
            buf,
            pos: 0,
            yield_counter: 0,
        }
    }

    /// Write all bytes from a buffer.
    fn write_all_buf<'a, B>(&'a mut self, buf: &'a mut B) -> WriteAllBuf<'a, Self, B>
    where
        Self: Unpin,
        B: Buf + Unpin + ?Sized,
    {
        WriteAllBuf {
            writer: self,
            buf,
            yield_counter: 0,
        }
    }

    /// Write a single byte.
    fn write_u8(&mut self, n: u8) -> WriteU8<'_, Self>
    where
        Self: Unpin,
    {
        WriteU8 {
            writer: self,
            byte: n,
        }
    }

    /// Flush buffered data.
    fn flush(&mut self) -> Flush<'_, Self>
    where
        Self: Unpin,
    {
        Flush { writer: self }
    }

    /// Shutdown the writer.
    fn shutdown(&mut self) -> Shutdown<'_, Self>
    where
        Self: Unpin,
    {
        Shutdown { writer: self }
    }

    /// Write data from multiple buffers (vectored I/O).
    fn write_vectored<'a>(&'a mut self, bufs: &'a [IoSlice<'a>]) -> WriteVectored<'a, Self>
    where
        Self: Unpin,
    {
        WriteVectored { writer: self, bufs }
    }
}

impl<W: AsyncWrite + ?Sized> AsyncWriteExt for W {}

/// Future for write_all.
pub struct WriteAll<'a, W: ?Sized> {
    writer: &'a mut W,
    buf: &'a [u8],
    pos: usize,
    yield_counter: u8,
}

impl<W> Future for WriteAll<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while this.pos < this.buf.len() {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            match Pin::new(&mut *this.writer).poll_write(cx, &this.buf[this.pos..]) {
                Poll::Pending => {
                    this.yield_counter = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    this.pos += n;
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

/// Future for write_all_buf.
pub struct WriteAllBuf<'a, W: ?Sized, B: ?Sized> {
    writer: &'a mut W,
    buf: &'a mut B,
    yield_counter: u8,
}

impl<W, B> Future for WriteAllBuf<'_, W, B>
where
    W: AsyncWrite + Unpin + ?Sized,
    B: Buf + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        while this.buf.remaining() > 0 {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            let chunk = this.buf.chunk();
            if chunk.is_empty() {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            match Pin::new(&mut *this.writer).poll_write(cx, chunk) {
                Poll::Pending => {
                    this.yield_counter = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    this.buf.advance(n);
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Future for writing a single byte.
pub struct WriteU8<'a, W: ?Sized> {
    writer: &'a mut W,
    byte: u8,
}

impl<W> Future for WriteU8<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let buf = [this.byte];
        match Pin::new(&mut *this.writer).poll_write(cx, &buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

/// Future for flush.
pub struct Flush<'a, W: ?Sized> {
    writer: &'a mut W,
}

impl<W> Future for Flush<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.writer).poll_flush(cx)
    }
}

/// Future for shutdown.
pub struct Shutdown<'a, W: ?Sized> {
    writer: &'a mut W,
}

impl<W> Future for Shutdown<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.writer).poll_shutdown(cx)
    }
}

/// Future for write_vectored.
pub struct WriteVectored<'a, W: ?Sized> {
    writer: &'a mut W,
    bufs: &'a [IoSlice<'a>],
}

impl<W> Future for WriteVectored<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.writer).poll_write_vectored(cx, this.bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn poll_ready<F: Future>(fut: &mut Pin<&mut F>) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..32 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return output;
            }
        }
        unreachable!("future did not resolve");
    }

    #[test]
    fn write_all_ok() {
        init_test("write_all_ok");
        let mut output = Vec::new();
        let mut fut = output.write_all(b"hello world");
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(output == b"hello world", "output", b"hello world", output);
        crate::test_complete!("write_all_ok");
    }

    #[test]
    fn write_u8_ok() {
        init_test("write_u8_ok");
        let mut output = Vec::new();
        let mut fut = output.write_u8(0x42);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(output == vec![0x42], "output", vec![0x42], output);
        crate::test_complete!("write_u8_ok");
    }

    #[test]
    fn flush_ok() {
        init_test("flush_ok");
        let mut output = Vec::new();
        let mut fut = output.flush();
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("flush_ok");
    }

    #[test]
    fn shutdown_ok() {
        init_test("shutdown_ok");
        let mut output = Vec::new();
        let mut fut = output.shutdown();
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("shutdown_ok");
    }

    #[test]
    fn write_vectored_ok() {
        init_test("write_vectored_ok");
        let mut output = Vec::new();
        let data1 = b"hello ";
        let data2 = b"world";
        let bufs = &[IoSlice::new(data1), IoSlice::new(data2)];
        let mut fut = output.write_vectored(bufs);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).unwrap();
        // Default implementation writes first non-empty buffer
        crate::assert_with_log!(n == 6, "bytes written", 6, n);
        crate::assert_with_log!(output == b"hello ", "output", b"hello ", output);
        crate::test_complete!("write_vectored_ok");
    }

    #[test]
    fn write_all_buf_ok() {
        init_test("write_all_buf_ok");
        let mut output = Vec::new();
        let mut input: &[u8] = b"buffered";
        let mut fut = output.write_all_buf(&mut input);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let empty = input.is_empty();
        crate::assert_with_log!(empty, "input empty", true, empty);
        crate::assert_with_log!(output == b"buffered", "output", b"buffered", output);
        crate::test_complete!("write_all_buf_ok");
    }
}
