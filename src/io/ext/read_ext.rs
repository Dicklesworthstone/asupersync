//! AsyncRead extension methods.

use crate::io::{AsyncRead, AsyncReadVectored, Chain, ReadBuf, Take};
use std::future::Future;
use std::io::{self, ErrorKind, IoSliceMut};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Generates a trait method that returns a read-integer future.
macro_rules! read_int_trait_method {
    ($method:ident, $future:ident, $ty:ty, $size:literal, $order:literal) => {
        #[doc = concat!("Read a `", stringify!($ty), "` in ", $order, " byte order.")]
        ///
        /// Not cancel-safe: internal buffer may have been partially filled.
        fn $method(&mut self) -> $future<'_, Self>
        where
            Self: Unpin,
        {
            $future {
                reader: self,
                buf: [0u8; $size],
                pos: 0,
                completed: false,
            }
        }
    };
}

/// Extension trait for `AsyncRead`.
pub trait AsyncReadExt: AsyncRead {
    /// Read some bytes into `buf`, returning the number of bytes read.
    ///
    /// Returns 0 on EOF.
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel-safe: if dropped while waiting for data, no bytes
    /// have been read from the underlying stream and no data is lost.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Read<'a, Self>
    where
        Self: Unpin,
    {
        Read {
            reader: self,
            buf,
            completed: false,
        }
    }

    /// Read the exact number of bytes to fill `buf`.
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadExact<'a, Self>
    where
        Self: Unpin,
    {
        ReadExact {
            reader: self,
            buf,
            pos: 0,
            yield_counter: 0,
            completed: false,
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
            completed: false,
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
            start_len,
            read: 0,
            yield_counter: 0,
            completed: false,
        }
    }

    /// Read a single unsigned byte.
    fn read_u8(&mut self) -> ReadU8<'_, Self>
    where
        Self: Unpin,
    {
        ReadU8 {
            reader: self,
            completed: false,
        }
    }

    /// Read a single signed byte.
    fn read_i8(&mut self) -> ReadI8<'_, Self>
    where
        Self: Unpin,
    {
        ReadI8 {
            reader: self,
            completed: false,
        }
    }

    read_int_trait_method!(read_u16, ReadU16, u16, 2, "big-endian");
    read_int_trait_method!(read_u16_le, ReadU16Le, u16, 2, "little-endian");
    read_int_trait_method!(read_i16, ReadI16, i16, 2, "big-endian");
    read_int_trait_method!(read_i16_le, ReadI16Le, i16, 2, "little-endian");
    read_int_trait_method!(read_u32, ReadU32, u32, 4, "big-endian");
    read_int_trait_method!(read_u32_le, ReadU32Le, u32, 4, "little-endian");
    read_int_trait_method!(read_i32, ReadI32, i32, 4, "big-endian");
    read_int_trait_method!(read_i32_le, ReadI32Le, i32, 4, "little-endian");
    read_int_trait_method!(read_u64, ReadU64, u64, 8, "big-endian");
    read_int_trait_method!(read_u64_le, ReadU64Le, u64, 8, "little-endian");
    read_int_trait_method!(read_i64, ReadI64, i64, 8, "big-endian");
    read_int_trait_method!(read_i64_le, ReadI64Le, i64, 8, "little-endian");
    read_int_trait_method!(read_u128, ReadU128, u128, 16, "big-endian");
    read_int_trait_method!(read_u128_le, ReadU128Le, u128, 16, "little-endian");
    read_int_trait_method!(read_i128, ReadI128, i128, 16, "big-endian");
    read_int_trait_method!(read_i128_le, ReadI128Le, i128, 16, "little-endian");
    read_int_trait_method!(read_f32, ReadF32, f32, 4, "big-endian");
    read_int_trait_method!(read_f32_le, ReadF32Le, f32, 4, "little-endian");
    read_int_trait_method!(read_f64, ReadF64, f64, 8, "big-endian");
    read_int_trait_method!(read_f64_le, ReadF64Le, f64, 8, "little-endian");

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
        ReadVectored {
            reader: self,
            bufs,
            completed: false,
        }
    }
}

impl<R: AsyncReadVectored + ?Sized> AsyncReadVectoredExt for R {}

// ---------------------------------------------------------------------------
// Future types
// ---------------------------------------------------------------------------

/// Future for `read`.
pub struct Read<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut [u8],
    completed: bool,
}

impl<R> Future for Read<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other("Read future polled after completion")));
        }
        let mut read_buf = ReadBuf::new(this.buf);
        match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(())) => {
                this.completed = true;
                Poll::Ready(Ok(read_buf.filled().len()))
            }
        }
    }
}

/// Future for `read_vectored`.
pub struct ReadVectored<'a, R: ?Sized> {
    reader: &'a mut R,
    bufs: &'a mut [IoSliceMut<'a>],
    completed: bool,
}

impl<R> Future for ReadVectored<'_, R>
where
    R: AsyncReadVectored + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadVectored future polled after completion",
            )));
        }
        let result = Pin::new(&mut *this.reader).poll_read_vectored(cx, this.bufs);
        if result.is_ready() {
            this.completed = true;
        }
        result
    }
}

/// Future for `read_exact`.
pub struct ReadExact<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut [u8],
    pos: usize,
    yield_counter: u8,
    completed: bool,
}

impl<R> Future for ReadExact<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadExact future polled after completion",
            )));
        }

        while this.pos < this.buf.len() {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            let mut read_buf = ReadBuf::new(&mut this.buf[this.pos..]);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => {
                    this.yield_counter = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.completed = true;
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    this.pos += n;
                }
            }
        }

        this.completed = true;
        Poll::Ready(Ok(()))
    }
}

/// Future for `read_to_end`.
pub struct ReadToEnd<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut Vec<u8>,
    start_len: usize,
    yield_counter: u8,
    completed: bool,
}

impl<R> Future for ReadToEnd<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const CHUNK: usize = 8192;
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadToEnd future polled after completion",
            )));
        }

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
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.completed = true;
                        return Poll::Ready(Ok(this.buf.len().saturating_sub(this.start_len)));
                    }
                    this.buf.extend_from_slice(read_buf.filled());
                }
            }
        }
    }
}

/// Future for `read_to_string`.
pub struct ReadToString<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut String,
    pending_utf8: Vec<u8>,
    start_len: usize,
    read: usize,
    yield_counter: u8,
    completed: bool,
}

impl<R: ?Sized> ReadToString<'_, R> {
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
        const CHUNK: usize = 8192;
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadToString future polled after completion",
            )));
        }

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
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    this.buf.truncate(this.start_len);
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.completed = true;
                        if this.pending_utf8.is_empty() {
                            return Poll::Ready(Ok(this.read));
                        }
                        this.buf.truncate(this.start_len);
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "incomplete utf-8 sequence",
                        )));
                    }
                    this.read += n;
                    this.pending_utf8.extend_from_slice(read_buf.filled());
                    if let Err(err) = this.push_valid_prefix() {
                        this.completed = true;
                        this.buf.truncate(this.start_len);
                        return Poll::Ready(Err(err));
                    }
                }
            }
        }
    }
}

/// Future for reading a single unsigned byte.
pub struct ReadU8<'a, R: ?Sized> {
    reader: &'a mut R,
    completed: bool,
}

impl<R> Future for ReadU8<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<u8>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadU8 future polled after completion",
            )));
        }
        let mut one = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut one);
        match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(())) => {
                this.completed = true;
                if read_buf.filled().is_empty() {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                } else {
                    Poll::Ready(Ok(read_buf.filled()[0]))
                }
            }
        }
    }
}

/// Future for reading a single signed byte.
pub struct ReadI8<'a, R: ?Sized> {
    reader: &'a mut R,
    completed: bool,
}

impl<R> Future for ReadI8<'_, R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<i8>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadI8 future polled after completion",
            )));
        }
        let mut one = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut one);
        match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(())) => {
                this.completed = true;
                if read_buf.filled().is_empty() {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                } else {
                    Poll::Ready(Ok(read_buf.filled()[0].cast_signed()))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-byte integer/float read futures (macro-generated)
// ---------------------------------------------------------------------------

/// Generates a future struct + `Future` impl for reading a fixed-size integer.
macro_rules! read_int_future {
    ($future:ident, $ty:ty, $size:literal, $convert:expr) => {
        #[doc = concat!("Future for reading a `", stringify!($ty), "`.")]
        pub struct $future<'a, R: ?Sized> {
            reader: &'a mut R,
            buf: [u8; $size],
            pos: usize,
            completed: bool,
        }

        impl<R> Future for $future<'_, R>
        where
            R: AsyncRead + Unpin + ?Sized,
        {
            type Output = io::Result<$ty>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.get_mut();
                if this.completed {
                    return Poll::Ready(Err(io::Error::other(concat!(
                        stringify!($future),
                        " future polled after completion"
                    ))));
                }
                while this.pos < $size {
                    let mut read_buf = ReadBuf::new(&mut this.buf[this.pos..]);
                    match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.completed = true;
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                this.completed = true;
                                return Poll::Ready(Err(io::Error::from(
                                    io::ErrorKind::UnexpectedEof,
                                )));
                            }
                            this.pos += n;
                        }
                    }
                }
                this.completed = true;
                let convert: fn([u8; $size]) -> $ty = $convert;
                Poll::Ready(Ok(convert(this.buf)))
            }
        }
    };
}

read_int_future!(ReadU16, u16, 2, u16::from_be_bytes);
read_int_future!(ReadU16Le, u16, 2, u16::from_le_bytes);
read_int_future!(ReadI16, i16, 2, i16::from_be_bytes);
read_int_future!(ReadI16Le, i16, 2, i16::from_le_bytes);
read_int_future!(ReadU32, u32, 4, u32::from_be_bytes);
read_int_future!(ReadU32Le, u32, 4, u32::from_le_bytes);
read_int_future!(ReadI32, i32, 4, i32::from_be_bytes);
read_int_future!(ReadI32Le, i32, 4, i32::from_le_bytes);
read_int_future!(ReadU64, u64, 8, u64::from_be_bytes);
read_int_future!(ReadU64Le, u64, 8, u64::from_le_bytes);
read_int_future!(ReadI64, i64, 8, i64::from_be_bytes);
read_int_future!(ReadI64Le, i64, 8, i64::from_le_bytes);
read_int_future!(ReadU128, u128, 16, u128::from_be_bytes);
read_int_future!(ReadU128Le, u128, 16, u128::from_le_bytes);
read_int_future!(ReadI128, i128, 16, i128::from_be_bytes);
read_int_future!(ReadI128Le, i128, 16, i128::from_le_bytes);
read_int_future!(ReadF32, f32, 4, f32::from_be_bytes);
read_int_future!(ReadF32Le, f32, 4, f32::from_le_bytes);
read_int_future!(ReadF64, f64, 8, f64::from_be_bytes);
read_int_future!(ReadF64Le, f64, 8, f64::from_le_bytes);

#[cfg(test)]
#[path = "read_ext_inline_tests.rs"]
mod tests;
