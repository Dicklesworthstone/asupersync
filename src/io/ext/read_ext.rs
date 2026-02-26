//! AsyncRead extension methods.

use crate::io::{AsyncRead, AsyncReadVectored, Chain, ReadBuf, Take};
use std::future::Future;
use std::io::{self, ErrorKind, IoSliceMut};
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
        let start_len = buf.len();
        ReadToEnd {
            reader: self,
            buf,
            start_len,
            yield_counter: 0,
        }
    }

    /// Read the entire reader into `buf` as UTF-8.
    fn read_to_string<'a>(&'a mut self, buf: &'a mut String) -> ReadToString<'a, Self>
    where
        Self: Unpin,
    {
        let start_len = buf.len();
        ReadToString {
            reader: self,
            buf,
            pending_utf8: Vec::new(),
            read: 0,
            start_len,
            yield_counter: 0,
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

/// Extension trait for `AsyncReadVectored`.
pub trait AsyncReadVectoredExt: AsyncReadVectored {
    /// Read into multiple buffers (vectored I/O).
    fn read_vectored<'a>(&'a mut self, bufs: &'a mut [IoSliceMut<'a>]) -> ReadVectored<'a, Self>
    where
        Self: Unpin,
    {
        ReadVectored { reader: self, bufs }
    }
}

impl<R: AsyncReadVectored + ?Sized> AsyncReadVectoredExt for R {}

/// Future for read_vectored.
pub struct ReadVectored<'a, R: ?Sized> {
    reader: &'a mut R,
    bufs: &'a mut [IoSliceMut<'a>],
}

impl<R> Future for ReadVectored<'_, R>
where
    R: AsyncReadVectored + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.reader).poll_read_vectored(cx, this.bufs)
    }
}

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
    start_len: usize,
    yield_counter: u8,
}

impl<R> Future for ReadToEnd<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const CHUNK: usize = 1024;
        let this = self.get_mut();

        loop {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            let mut local = [0u8; CHUNK];
            let mut read_buf = ReadBuf::new(&mut local);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => {
                    this.yield_counter = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(this.buf.len().saturating_sub(this.start_len)));
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
    pending_utf8: Vec<u8>,
    read: usize,
    start_len: usize,
    yield_counter: u8,
}

impl<R: ?Sized> ReadToString<'_, R> {
    fn rollback_utf8_error(&mut self) {
        self.buf.truncate(self.start_len);
        self.pending_utf8.clear();
    }

    fn push_valid_prefix(&mut self) -> io::Result<()> {
        match std::str::from_utf8(&self.pending_utf8) {
            Ok(s) => {
                self.buf.push_str(s);
                self.pending_utf8.clear();
                Ok(())
            }
            Err(err) => {
                if err.error_len().is_some() {
                    return Err(io::Error::new(ErrorKind::InvalidData, "invalid utf-8"));
                }

                let valid_up_to = err.valid_up_to();
                if valid_up_to == 0 {
                    return Ok(());
                }
                let valid = &self.pending_utf8[..valid_up_to];
                let valid_str = std::str::from_utf8(valid)
                    .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid utf-8"))?;
                self.buf.push_str(valid_str);
                self.pending_utf8 = self.pending_utf8[valid_up_to..].to_vec();
                Ok(())
            }
        }
    }
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
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            let mut local = [0u8; CHUNK];
            let mut read_buf = ReadBuf::new(&mut local);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => {
                    this.yield_counter = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if this.pending_utf8.is_empty() {
                            return Poll::Ready(Ok(this.read));
                        }
                        this.rollback_utf8_error();
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "incomplete utf-8 sequence",
                        )));
                    }
                    this.read += n;
                    this.pending_utf8.extend_from_slice(read_buf.filled());
                    if let Err(err) = this.push_valid_prefix() {
                        this.rollback_utf8_error();
                        return Poll::Ready(Err(err));
                    }
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
    use std::io::IoSliceMut;
    use std::pin::Pin;
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

    fn poll_ready<F: Future>(fut: &mut Pin<&mut F>) -> Option<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..32 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return Some(output);
            }
        }
        None
    }

    #[test]
    fn read_exact_ok() {
        init_test("read_exact_ok");
        let mut reader: &[u8] = b"abcd";
        let mut buf = [0u8; 4];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut).expect("future did not resolve");
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(&buf == b"abcd", "buf", b"abcd", buf);
        crate::test_complete!("read_exact_ok");
    }

    #[test]
    fn read_exact_eof() {
        init_test("read_exact_eof");
        let mut reader: &[u8] = b"ab";
        let mut buf = [0u8; 4];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::UnexpectedEof,
            "error kind",
            io::ErrorKind::UnexpectedEof,
            kind
        );
        crate::test_complete!("read_exact_eof");
    }

    #[test]
    fn read_to_end_reads_all() {
        init_test("read_to_end_reads_all");
        let mut reader: &[u8] = b"hello";
        let mut buf = Vec::new();
        let mut fut = reader.read_to_end(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 5, "bytes read", 5, n);
        crate::assert_with_log!(buf == b"hello", "buf", b"hello", buf);
        crate::test_complete!("read_to_end_reads_all");
    }

    #[test]
    fn read_to_string_reads_all() {
        init_test("read_to_string_reads_all");
        let mut reader: &[u8] = b"hi";
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 2, "bytes read", 2, n);
        crate::assert_with_log!(buf == "hi", "buf", "hi", buf);
        crate::test_complete!("read_to_string_reads_all");
    }

    #[test]
    fn read_to_string_invalid_utf8_errors() {
        init_test("read_to_string_invalid_utf8_errors");
        let mut reader: &[u8] = &[0xff, 0xfe];
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        let empty = buf.is_empty();
        crate::assert_with_log!(empty, "buf empty", true, empty);
        crate::test_complete!("read_to_string_invalid_utf8_errors");
    }

    #[test]
    fn read_to_string_incomplete_utf8_errors() {
        init_test("read_to_string_incomplete_utf8_errors");
        // 4-byte UTF-8 sequence, missing the final byte.
        let mut reader: &[u8] = &[0xF0, 0x9F, 0x92];
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        let empty = buf.is_empty();
        crate::assert_with_log!(empty, "buf empty", true, empty);
        crate::test_complete!("read_to_string_incomplete_utf8_errors");
    }

    #[test]
    fn read_to_string_invalid_utf8_rolls_back_after_long_valid_prefix() {
        init_test("read_to_string_invalid_utf8_rolls_back_after_long_valid_prefix");
        let mut input = vec![b'a'; 1024];
        input.push(0xFF);
        let mut reader: &[u8] = &input;
        let mut buf = String::from("seed");
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        crate::assert_with_log!(buf == "seed", "buf rollback", "seed", buf);
        crate::test_complete!("read_to_string_invalid_utf8_rolls_back_after_long_valid_prefix");
    }

    #[test]
    fn read_to_string_incomplete_utf8_rolls_back_after_long_valid_prefix() {
        init_test("read_to_string_incomplete_utf8_rolls_back_after_long_valid_prefix");
        let mut input = vec![b'a'; 1024];
        input.extend_from_slice(&[0xF0, 0x9F, 0x92]);
        let mut reader: &[u8] = &input;
        let mut buf = String::from("seed");
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        crate::assert_with_log!(buf == "seed", "buf rollback", "seed", buf);
        crate::test_complete!("read_to_string_incomplete_utf8_rolls_back_after_long_valid_prefix");
    }

    #[test]
    fn read_u8_reads_byte() {
        init_test("read_u8_reads_byte");
        let mut reader: &[u8] = b"z";
        let mut fut = reader.read_u8();
        let mut fut = Pin::new(&mut fut);
        let byte = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(byte == b'z', "byte", b'z', byte);
        crate::test_complete!("read_u8_reads_byte");
    }

    #[test]
    fn read_vectored_reads_prefix() {
        init_test("read_vectored_reads_prefix");
        let mut reader: &[u8] = b"hello";
        let mut a = [0u8; 2];
        let mut b = [0u8; 3];
        let mut bufs = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];

        let mut fut = reader.read_vectored(&mut bufs);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect("read_vectored failed");

        let mut got = Vec::new();
        let first = n.min(a.len());
        got.extend_from_slice(&a[..first]);
        if n > a.len() {
            got.extend_from_slice(&b[..n - a.len()]);
        }

        let expected = b"hello";
        crate::assert_with_log!(got == expected[..n], "vectored prefix", &expected[..n], got);
        crate::test_complete!("read_vectored_reads_prefix");
    }

    #[derive(Debug)]
    struct YieldingReader<'a> {
        data: &'a [u8],
        pos: usize,
        yield_next: bool,
    }

    impl<'a> YieldingReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                data,
                pos: 0,
                yield_next: false,
            }
        }
    }

    impl AsyncRead for YieldingReader<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.yield_next {
                self.yield_next = false;
                return Poll::Pending;
            }

            if self.pos >= self.data.len() {
                return Poll::Ready(Ok(()));
            }

            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            buf.put_slice(&self.data[self.pos..=self.pos]);
            self.pos += 1;
            self.yield_next = true;

            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn cancel_safety_read_exact_is_not_cancel_safe() {
        init_test("cancel_safety_read_exact_is_not_cancel_safe");
        let mut reader = YieldingReader::new(b"abc");
        let mut buf = [0u8; 3];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = {
            let mut fut = reader.read_exact(&mut buf);
            let mut pinned = Pin::new(&mut fut);
            pinned.as_mut().poll(&mut cx)
        };
        let pending = matches!(poll, Poll::Pending);
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::assert_with_log!(buf[0] == b'a', "prefix", b'a', buf[0]);
        crate::test_complete!("cancel_safety_read_exact_is_not_cancel_safe");
    }

    #[test]
    fn cancel_safety_read_to_end_preserves_bytes() {
        init_test("cancel_safety_read_to_end_preserves_bytes");
        let mut reader = YieldingReader::new(b"abc");
        let mut out = Vec::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = {
            let mut fut = reader.read_to_end(&mut out);
            let mut pinned = Pin::new(&mut fut);
            pinned.as_mut().poll(&mut cx)
        };
        let pending = matches!(poll, Poll::Pending);
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::assert_with_log!(out == b"a", "out", b"a", out);
        crate::test_complete!("cancel_safety_read_to_end_preserves_bytes");
    }

    #[test]
    fn cancel_safety_read_to_string_preserves_prefix() {
        init_test("cancel_safety_read_to_string_preserves_prefix");
        let mut reader = YieldingReader::new(b"abc");
        let mut out = String::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = {
            let mut fut = reader.read_to_string(&mut out);
            let mut pinned = Pin::new(&mut fut);
            pinned.as_mut().poll(&mut cx)
        };
        let pending = matches!(poll, Poll::Pending);
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::assert_with_log!(out == "a", "out", "a", out);
        crate::test_complete!("cancel_safety_read_to_string_preserves_prefix");
    }
}
