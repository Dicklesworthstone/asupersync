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

/// Generates a trait method that returns a write-integer future.
macro_rules! write_int_trait_method {
    ($method:ident, $future:ident, $ty:ty, $size:literal, $order:literal, $to_bytes:ident) => {
        #[doc = concat!("Write a `", stringify!($ty), "` in ", $order, " byte order.")]
        ///
        /// Not cancel-safe: partial writes may have occurred.
        fn $method(&mut self, n: $ty) -> $future<'_, Self>
        where
            Self: Unpin,
        {
            $future {
                writer: self,
                buf: n.$to_bytes(),
                pos: 0,
                completed: false,
            }
        }
    };
}

/// Extension trait for `AsyncWrite`.
pub trait AsyncWriteExt: AsyncWrite {
    /// Write some bytes from `buf`, returning the number of bytes written.
    ///
    /// Returns 0 only if `buf` is empty or the writer is closed.
    /// Not cancel-safe.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Write<'a, Self>
    where
        Self: Unpin,
    {
        Write {
            writer: self,
            buf,
            completed: false,
        }
    }

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
            completed: false,
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
            completed: false,
        }
    }

    /// Write a single unsigned byte.
    fn write_u8(&mut self, n: u8) -> WriteU8<'_, Self>
    where
        Self: Unpin,
    {
        WriteU8 {
            writer: self,
            byte: n,
            completed: false,
        }
    }

    /// Write a single signed byte.
    fn write_i8(&mut self, n: i8) -> WriteI8<'_, Self>
    where
        Self: Unpin,
    {
        WriteI8 {
            writer: self,
            byte: n.cast_unsigned(),
            completed: false,
        }
    }

    write_int_trait_method!(write_u16, WriteU16, u16, 2, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_u16_le,
        WriteU16Le,
        u16,
        2,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_i16, WriteI16, i16, 2, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_i16_le,
        WriteI16Le,
        i16,
        2,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_u32, WriteU32, u32, 4, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_u32_le,
        WriteU32Le,
        u32,
        4,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_i32, WriteI32, i32, 4, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_i32_le,
        WriteI32Le,
        i32,
        4,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_u64, WriteU64, u64, 8, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_u64_le,
        WriteU64Le,
        u64,
        8,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_i64, WriteI64, i64, 8, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_i64_le,
        WriteI64Le,
        i64,
        8,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_u128, WriteU128, u128, 16, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_u128_le,
        WriteU128Le,
        u128,
        16,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_i128, WriteI128, i128, 16, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_i128_le,
        WriteI128Le,
        i128,
        16,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_f32, WriteF32, f32, 4, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_f32_le,
        WriteF32Le,
        f32,
        4,
        "little-endian",
        to_le_bytes
    );
    write_int_trait_method!(write_f64, WriteF64, f64, 8, "big-endian", to_be_bytes);
    write_int_trait_method!(
        write_f64_le,
        WriteF64Le,
        f64,
        8,
        "little-endian",
        to_le_bytes
    );

    /// Flush buffered data.
    fn flush(&mut self) -> Flush<'_, Self>
    where
        Self: Unpin,
    {
        Flush {
            writer: self,
            completed: false,
        }
    }

    /// Shutdown the writer.
    fn shutdown(&mut self) -> Shutdown<'_, Self>
    where
        Self: Unpin,
    {
        Shutdown {
            writer: self,
            completed: false,
        }
    }

    /// Write data from multiple buffers (vectored I/O).
    fn write_vectored<'a>(&'a mut self, bufs: &'a [IoSlice<'a>]) -> WriteVectored<'a, Self>
    where
        Self: Unpin,
    {
        WriteVectored {
            writer: self,
            bufs,
            completed: false,
        }
    }
}

impl<W: AsyncWrite + ?Sized> AsyncWriteExt for W {}

// ---------------------------------------------------------------------------
// Future types
// ---------------------------------------------------------------------------

/// Future for `write`.
pub struct Write<'a, W: ?Sized> {
    writer: &'a mut W,
    buf: &'a [u8],
    completed: bool,
}

impl<W> Future for Write<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "Write future polled after completion",
            )));
        }
        let result = Pin::new(&mut *this.writer).poll_write(cx, this.buf);
        if result.is_ready() {
            this.completed = true;
        }
        result
    }
}

/// Future for `write_all`.
pub struct WriteAll<'a, W: ?Sized> {
    writer: &'a mut W,
    buf: &'a [u8],
    pos: usize,
    yield_counter: u8,
    completed: bool,
}

impl<W> Future for WriteAll<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "WriteAll future polled after completion",
            )));
        }

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
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        this.completed = true;
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    this.pos += n;
                }
            }
        }

        this.completed = true;
        Poll::Ready(Ok(()))
    }
}

/// Future for `write_all_buf`.
pub struct WriteAllBuf<'a, W: ?Sized, B: ?Sized> {
    writer: &'a mut W,
    buf: &'a mut B,
    yield_counter: u8,
    completed: bool,
}

impl<W, B> Future for WriteAllBuf<'_, W, B>
where
    W: AsyncWrite + Unpin + ?Sized,
    B: Buf + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "WriteAllBuf future polled after completion",
            )));
        }
        while this.buf.remaining() > 0 {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            let chunk = this.buf.chunk();
            if chunk.is_empty() {
                this.completed = true;
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            match Pin::new(&mut *this.writer).poll_write(cx, chunk) {
                Poll::Pending => {
                    this.yield_counter = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        this.completed = true;
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    this.buf.advance(n);
                }
            }
        }
        this.completed = true;
        Poll::Ready(Ok(()))
    }
}

/// Future for writing a single unsigned byte.
pub struct WriteU8<'a, W: ?Sized> {
    writer: &'a mut W,
    byte: u8,
    completed: bool,
}

impl<W> Future for WriteU8<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "WriteU8 future polled after completion",
            )));
        }
        let buf = [this.byte];
        match Pin::new(&mut *this.writer).poll_write(cx, &buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(n)) => {
                this.completed = true;
                if n == 0 {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

/// Future for writing a single signed byte.
pub struct WriteI8<'a, W: ?Sized> {
    writer: &'a mut W,
    byte: u8,
    completed: bool,
}

impl<W> Future for WriteI8<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "WriteI8 future polled after completion",
            )));
        }
        let buf = [this.byte];
        match Pin::new(&mut *this.writer).poll_write(cx, &buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(n)) => {
                this.completed = true;
                if n == 0 {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

/// Future for `flush`.
pub struct Flush<'a, W: ?Sized> {
    writer: &'a mut W,
    completed: bool,
}

impl<W> Future for Flush<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "Flush future polled after completion",
            )));
        }
        let result = Pin::new(&mut *this.writer).poll_flush(cx);
        if result.is_ready() {
            this.completed = true;
        }
        result
    }
}

/// Future for `shutdown`.
pub struct Shutdown<'a, W: ?Sized> {
    writer: &'a mut W,
    completed: bool,
}

impl<W> Future for Shutdown<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "Shutdown future polled after completion",
            )));
        }
        let result = Pin::new(&mut *this.writer).poll_shutdown(cx);
        if result.is_ready() {
            this.completed = true;
        }
        result
    }
}

/// Future for `write_vectored`.
pub struct WriteVectored<'a, W: ?Sized> {
    writer: &'a mut W,
    bufs: &'a [IoSlice<'a>],
    completed: bool,
}

impl<W> Future for WriteVectored<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "WriteVectored future polled after completion",
            )));
        }
        let result = Pin::new(&mut *this.writer).poll_write_vectored(cx, this.bufs);
        if result.is_ready() {
            this.completed = true;
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Multi-byte integer/float write futures (macro-generated)
// ---------------------------------------------------------------------------

/// Generates a future struct + `Future` impl for writing a fixed-size value.
macro_rules! write_int_future {
    ($future:ident, $ty:ty, $size:literal) => {
        #[doc = concat!("Future for writing a `", stringify!($ty), "`.")]
        pub struct $future<'a, W: ?Sized> {
            writer: &'a mut W,
            buf: [u8; $size],
            pos: usize,
            completed: bool,
        }

        impl<W> Future for $future<'_, W>
        where
            W: AsyncWrite + Unpin + ?Sized,
        {
            type Output = io::Result<()>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.get_mut();
                if this.completed {
                    return Poll::Ready(Err(io::Error::other(concat!(
                        stringify!($future),
                        " future polled after completion"
                    ))));
                }
                while this.pos < $size {
                    match Pin::new(&mut *this.writer).poll_write(cx, &this.buf[this.pos..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.completed = true;
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(n)) => {
                            if n == 0 {
                                this.completed = true;
                                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                            }
                            this.pos += n;
                        }
                    }
                }
                this.completed = true;
                Poll::Ready(Ok(()))
            }
        }
    };
}

write_int_future!(WriteU16, u16, 2);
write_int_future!(WriteU16Le, u16, 2);
write_int_future!(WriteI16, i16, 2);
write_int_future!(WriteI16Le, i16, 2);
write_int_future!(WriteU32, u32, 4);
write_int_future!(WriteU32Le, u32, 4);
write_int_future!(WriteI32, i32, 4);
write_int_future!(WriteI32Le, i32, 4);
write_int_future!(WriteU64, u64, 8);
write_int_future!(WriteU64Le, u64, 8);
write_int_future!(WriteI64, i64, 8);
write_int_future!(WriteI64Le, i64, 8);
write_int_future!(WriteU128, u128, 16);
write_int_future!(WriteU128Le, u128, 16);
write_int_future!(WriteI128, i128, 16);
write_int_future!(WriteI128Le, i128, 16);
write_int_future!(WriteF32, f32, 4);
write_int_future!(WriteF32Le, f32, 4);
write_int_future!(WriteF64, f64, 8);
write_int_future!(WriteF64Le, f64, 8);

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
    fn write_basic_returns_bytes_written() {
        init_test("write_basic_returns_bytes_written");
        let mut output = Vec::new();
        let mut fut = output.write(b"hello");
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).unwrap();
        crate::assert_with_log!(n == 5, "bytes written", 5, n);
        crate::assert_with_log!(output == b"hello", "output", b"hello", output);
        crate::test_complete!("write_basic_returns_bytes_written");
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
    fn write_i8_ok() {
        init_test("write_i8_ok");
        let mut output = Vec::new();
        let mut fut = output.write_i8(-2);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(output == vec![0xFE], "output", vec![0xFE], output);
        crate::test_complete!("write_i8_ok");
    }

    #[test]
    fn write_u16_big_endian() {
        init_test("write_u16_big_endian");
        let mut output = Vec::new();
        let mut fut = output.write_u16(0x0102);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(
            output == vec![0x01, 0x02],
            "output BE",
            vec![0x01, 0x02],
            output
        );
        crate::test_complete!("write_u16_big_endian");
    }

    #[test]
    fn write_u16_le_little_endian() {
        init_test("write_u16_le_little_endian");
        let mut output = Vec::new();
        let mut fut = output.write_u16_le(0x0102);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(
            output == vec![0x02, 0x01],
            "output LE",
            vec![0x02, 0x01],
            output
        );
        crate::test_complete!("write_u16_le_little_endian");
    }

    #[test]
    fn write_u32_big_endian() {
        init_test("write_u32_big_endian");
        let mut output = Vec::new();
        let mut fut = output.write_u32(0x0102_0304);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let expected = vec![0x01, 0x02, 0x03, 0x04];
        crate::assert_with_log!(output == expected, "output BE", expected, output);
        crate::test_complete!("write_u32_big_endian");
    }

    #[test]
    fn write_f64_le_little_endian() {
        init_test("write_f64_le_little_endian");
        let val: f64 = core::f64::consts::PI;
        let mut output = Vec::new();
        let mut fut = output.write_f64_le(val);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let expected = val.to_le_bytes().to_vec();
        crate::assert_with_log!(output == expected, "output f64 LE", expected, output);
        crate::test_complete!("write_f64_le_little_endian");
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
        // Vec's write_vectored writes all buffers.
        crate::assert_with_log!(n == 11, "bytes written", 11, n);
        crate::assert_with_log!(output == b"hello world", "output", b"hello world", output);
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

    #[test]
    fn write_read_roundtrip_u32() {
        use crate::io::ext::read_ext::AsyncReadExt;
        init_test("write_read_roundtrip_u32");
        let expected: u32 = 0xDEAD_BEEF;
        let mut output = Vec::new();

        // Write
        let mut fut = output.write_u32(expected);
        let mut fut = Pin::new(&mut fut);
        poll_ready(&mut fut).unwrap();

        // Read back
        let mut reader: &[u8] = &output;
        let mut fut = reader.read_u32();
        let mut fut = Pin::new(&mut fut);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let val = match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(v)) => v,
            other => panic!("unexpected poll result: {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(val == expected, "roundtrip u32", expected, val);
        crate::test_complete!("write_read_roundtrip_u32");
    }
}
