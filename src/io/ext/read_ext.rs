//! AsyncRead extension methods.

use crate::io::{AsyncRead, Chain, ReadBuf, Take};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Extension trait for `AsyncRead`.
pub trait AsyncReadExt: AsyncRead {
    /// Read the exact number of bytes to fill `buf`.
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadExact<'a, Self>
    where
        Self: Unpin,
    {
        ReadExact {
            reader: self,
            buf,
            pos: 0,
        }
    }

    /// Read the entire reader into `buf`.
    fn read_to_end<'a>(&'a mut self, buf: &'a mut Vec<u8>) -> ReadToEnd<'a, Self>
    where
        Self: Unpin,
    {
        ReadToEnd { reader: self, buf }
    }

    /// Read the entire reader into `buf` as UTF-8.
    fn read_to_string<'a>(&'a mut self, buf: &'a mut String) -> ReadToString<'a, Self>
    where
        Self: Unpin,
    {
        ReadToString {
            reader: self,
            buf,
            bytes: Vec::new(),
        }
    }

    /// Read a single byte.
    fn read_u8(&mut self) -> ReadU8<'_, Self>
    where
        Self: Unpin,
    {
        ReadU8 { reader: self }
    }

    /// Chain this reader with another.
    fn chain<R: AsyncRead>(self, next: R) -> Chain<Self, R>
    where
        Self: Sized,
    {
        Chain::new(self, next)
    }

    /// Take at most `limit` bytes from this reader.
    fn take(self, limit: u64) -> Take<Self>
    where
        Self: Sized,
    {
        Take::new(self, limit)
    }
}

impl<R: AsyncRead + ?Sized> AsyncReadExt for R {}

/// Future for read_exact.
pub struct ReadExact<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut [u8],
    pos: usize,
}

impl<R> Future for ReadExact<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while this.pos < this.buf.len() {
            let mut read_buf = ReadBuf::new(&mut this.buf[this.pos..]);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    this.pos += n;
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

/// Future for read_to_end.
pub struct ReadToEnd<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut Vec<u8>,
}

impl<R> Future for ReadToEnd<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const CHUNK: usize = 1024;
        let this = self.get_mut();
        let start_len = this.buf.len();

        loop {
            let mut local = [0u8; CHUNK];
            let mut read_buf = ReadBuf::new(&mut local);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(this.buf.len() - start_len));
                    }
                    this.buf.extend_from_slice(read_buf.filled());
                }
            }
        }
    }
}

/// Future for read_to_string.
pub struct ReadToString<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut String,
    bytes: Vec<u8>,
}

impl<R> Future for ReadToString<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const CHUNK: usize = 1024;
        let this = self.get_mut();

        loop {
            let mut local = [0u8; CHUNK];
            let mut read_buf = ReadBuf::new(&mut local);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        let string = String::from_utf8(std::mem::take(&mut this.bytes))
                            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                        let added = string.len();
                        this.buf.push_str(&string);
                        return Poll::Ready(Ok(added));
                    }
                    this.bytes.extend_from_slice(read_buf.filled());
                }
            }
        }
    }
}

/// Future for reading a single byte.
pub struct ReadU8<'a, R: ?Sized> {
    reader: &'a mut R,
}

impl<R> Future for ReadU8<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<u8>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut one = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut one);
        match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                } else {
                    Poll::Ready(Ok(read_buf.filled()[0]))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

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
        panic!("future did not resolve");
    }

    #[test]
    fn read_exact_ok() {
        let mut reader: &[u8] = b"abcd";
        let mut buf = [0u8; 4];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        assert!(result.is_ok());
        assert_eq!(&buf, b"abcd");
    }

    #[test]
    fn read_exact_eof() {
        let mut reader: &[u8] = b"ab";
        let mut buf = [0u8; 4];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_to_end_reads_all() {
        let mut reader: &[u8] = b"hello";
        let mut buf = Vec::new();
        let mut fut = reader.read_to_end(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn read_to_string_reads_all() {
        let mut reader: &[u8] = b"hi";
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, "hi");
    }

    #[test]
    fn read_u8_reads_byte() {
        let mut reader: &[u8] = b"z";
        let mut fut = reader.read_u8();
        let mut fut = Pin::new(&mut fut);
        let byte = poll_ready(&mut fut).unwrap();
        assert_eq!(byte, b'z');
    }
}
