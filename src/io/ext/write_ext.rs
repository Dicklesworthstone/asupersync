//! AsyncWrite extension methods.

use crate::io::AsyncWrite;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

#[allow(dead_code)]
fn deterministic_f32_be_bytes(value: f32) -> [u8; 4] {
    deterministic_f32_bits(value).to_be_bytes()
}

#[allow(dead_code)]
fn deterministic_f32_le_bytes(value: f32) -> [u8; 4] {
    deterministic_f32_bits(value).to_le_bytes()
}

#[allow(dead_code)]
fn deterministic_f64_be_bytes(value: f64) -> [u8; 8] {
    deterministic_f64_bits(value).to_be_bytes()
}

#[allow(dead_code)]
fn deterministic_f64_le_bytes(value: f64) -> [u8; 8] {
    deterministic_f64_bits(value).to_le_bytes()
}

#[allow(dead_code)]
fn deterministic_f32_bits(value: f32) -> u32 {
    const CANONICAL_NAN_BITS: u32 = 0x7fc0_0000;
    if value.is_nan() {
        CANONICAL_NAN_BITS
    } else if value == 0.0 {
        0
    } else {
        value.to_bits()
    }
}

#[allow(dead_code)]
fn deterministic_f64_bits(value: f64) -> u64 {
    const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
    if value.is_nan() {
        CANONICAL_NAN_BITS
    } else if value == 0.0 {
        0
    } else {
        value.to_bits()
    }
}

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
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel-safe: if dropped while waiting for write readiness,
    /// no bytes have been written and no data is lost.
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
    /// Write a `f32` in big-endian byte order.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f32(&mut self, n: f32) -> WriteF32<'_, Self>
    where
        Self: Unpin,
    {
        WriteF32 {
            writer: self,
            buf: n.to_be_bytes(),
            pos: 0,
            completed: false,
        }
    }

    /// Write a `f32` in little-endian byte order.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f32_le(&mut self, n: f32) -> WriteF32Le<'_, Self>
    where
        Self: Unpin,
    {
        WriteF32Le {
            writer: self,
            buf: n.to_le_bytes(),
            pos: 0,
            completed: false,
        }
    }

    /// Write a `f64` in big-endian byte order.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f64(&mut self, n: f64) -> WriteF64<'_, Self>
    where
        Self: Unpin,
    {
        WriteF64 {
            writer: self,
            buf: n.to_be_bytes(),
            pos: 0,
            completed: false,
        }
    }

    /// Write a `f64` in little-endian byte order.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f64_le(&mut self, n: f64) -> WriteF64Le<'_, Self>
    where
        Self: Unpin,
    {
        WriteF64Le {
            writer: self,
            buf: n.to_le_bytes(),
            pos: 0,
            completed: false,
        }
    }

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

fn checked_write_count(n: usize, offered: usize) -> io::Result<usize> {
    if n > offered {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("writer reported {n} bytes written for {offered}-byte buffer"),
        ))
    } else {
        Ok(n)
    }
}

fn checked_write_progress(n: usize, remaining: usize) -> io::Result<usize> {
    let n = checked_write_count(n, remaining)?;
    if n == 0 && remaining > 0 {
        Err(io::Error::from(io::ErrorKind::WriteZero))
    } else {
        Ok(n)
    }
}

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
        match Pin::new(&mut *this.writer).poll_write(cx, this.buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(n)) => {
                this.completed = true;
                match checked_write_count(n, this.buf.len()) {
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
        }
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
                    let remaining = this.buf.len() - this.pos;
                    let n = match checked_write_progress(n, remaining) {
                        Ok(n) => n,
                        Err(err) => {
                            this.completed = true;
                            return Poll::Ready(Err(err));
                        }
                    };
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
                    let n = match checked_write_progress(n, chunk.len()) {
                        Ok(n) => n,
                        Err(err) => {
                            this.completed = true;
                            return Poll::Ready(Err(err));
                        }
                    };
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
                match checked_write_progress(n, 1) {
                    Ok(_) => Poll::Ready(Ok(())),
                    Err(err) => Poll::Ready(Err(err)),
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
                match checked_write_progress(n, 1) {
                    Ok(_) => Poll::Ready(Ok(())),
                    Err(err) => Poll::Ready(Err(err)),
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
        match Pin::new(&mut *this.writer).poll_write_vectored(cx, this.bufs) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(n)) => {
                this.completed = true;
                let remaining = this
                    .bufs
                    .iter()
                    .try_fold(0usize, |total, buf| total.checked_add(buf.len()))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "vectored buffers too large")
                    });
                match remaining.and_then(|remaining| checked_write_count(n, remaining)) {
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
        }
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
                            let remaining = $size - this.pos;
                            let n = match checked_write_progress(n, remaining) {
                                Ok(n) => n,
                                Err(err) => {
                                    this.completed = true;
                                    return Poll::Ready(Err(err));
                                }
                            };
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
#[path = "write_ext_inline_tests.rs"]
mod tests;
