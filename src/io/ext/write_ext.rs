//! AsyncWrite extension methods.

use crate::io::AsyncWrite;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

fn deterministic_f32_be_bytes(value: f32) -> [u8; 4] {
    deterministic_f32_bits(value).to_be_bytes()
}

fn deterministic_f32_le_bytes(value: f32) -> [u8; 4] {
    deterministic_f32_bits(value).to_le_bytes()
}

fn deterministic_f64_be_bytes(value: f64) -> [u8; 8] {
    deterministic_f64_bits(value).to_be_bytes()
}

fn deterministic_f64_le_bytes(value: f64) -> [u8; 8] {
    deterministic_f64_bits(value).to_le_bytes()
}

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
    /// Write a `f32` in big-endian byte order using deterministic float encoding.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f32(&mut self, n: f32) -> WriteF32<'_, Self>
    where
        Self: Unpin,
    {
        WriteF32 {
            writer: self,
            buf: deterministic_f32_be_bytes(n),
            pos: 0,
            completed: false,
        }
    }

    /// Write a `f32` in little-endian byte order using deterministic float encoding.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f32_le(&mut self, n: f32) -> WriteF32Le<'_, Self>
    where
        Self: Unpin,
    {
        WriteF32Le {
            writer: self,
            buf: deterministic_f32_le_bytes(n),
            pos: 0,
            completed: false,
        }
    }

    /// Write a `f64` in big-endian byte order using deterministic float encoding.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f64(&mut self, n: f64) -> WriteF64<'_, Self>
    where
        Self: Unpin,
    {
        WriteF64 {
            writer: self,
            buf: deterministic_f64_be_bytes(n),
            pos: 0,
            completed: false,
        }
    }

    /// Write a `f64` in little-endian byte order using deterministic float encoding.
    ///
    /// Not cancel-safe: partial writes may have occurred.
    fn write_f64_le(&mut self, n: f64) -> WriteF64Le<'_, Self>
    where
        Self: Unpin,
    {
        WriteF64Le {
            writer: self,
            buf: deterministic_f64_le_bytes(n),
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

fn checked_write_progress(n: usize, remaining: usize) -> io::Result<usize> {
    if n > remaining {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("writer reported {n} bytes written for {remaining}-byte buffer"),
        ))
    } else if n == 0 && remaining > 0 {
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
                match checked_write_progress(n, this.buf.len()) {
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
                match remaining.and_then(|remaining| checked_write_progress(n, remaining)) {
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    use std::task::{Context, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct OverreportingWriter {
        written: Vec<u8>,
    }

    impl OverreportingWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
            }
        }
    }

    impl AsyncWrite for OverreportingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len() + 1))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut total = 0usize;
            for buf in bufs {
                this.written.extend_from_slice(buf);
                total += buf.len();
            }
            Poll::Ready(Ok(total + 1))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PanicOnUseWriter;

    impl AsyncWrite for PanicOnUseWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            panic!("empty write_all must not poll the writer")
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            panic!("empty write_all must not poll vectored writes")
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("empty write_all must not poll flush")
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("empty write_all must not poll shutdown")
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum ControlStep {
        Pending,
        ReadyOk,
        ReadyErr(io::ErrorKind),
    }

    #[derive(Debug)]
    struct ScriptedControlWriter {
        flush_steps: std::collections::VecDeque<ControlStep>,
        shutdown_steps: std::collections::VecDeque<ControlStep>,
        flush_polls: usize,
        shutdown_polls: usize,
        expected_waker: Waker,
        saw_expected_waker: bool,
    }

    impl ScriptedControlWriter {
        fn new(
            expected_waker: Waker,
            flush_steps: impl IntoIterator<Item = ControlStep>,
            shutdown_steps: impl IntoIterator<Item = ControlStep>,
        ) -> Self {
            Self {
                flush_steps: flush_steps.into_iter().collect(),
                shutdown_steps: shutdown_steps.into_iter().collect(),
                flush_polls: 0,
                shutdown_polls: 0,
                expected_waker,
                saw_expected_waker: false,
            }
        }

        fn poll_control(
            steps: &mut std::collections::VecDeque<ControlStep>,
        ) -> Poll<io::Result<()>> {
            match steps.pop_front().expect("control script exhausted") {
                ControlStep::Pending => Poll::Pending,
                ControlStep::ReadyOk => Poll::Ready(Ok(())),
                ControlStep::ReadyErr(kind) => Poll::Ready(Err(io::Error::from(kind))),
            }
        }
    }

    impl AsyncWrite for ScriptedControlWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bufs.iter().map(|buf| buf.len()).sum()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_polls += 1;
            self.saw_expected_waker = cx.waker().will_wake(&self.expected_waker);
            Self::poll_control(&mut self.flush_steps)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_polls += 1;
            self.saw_expected_waker = cx.waker().will_wake(&self.expected_waker);
            Self::poll_control(&mut self.shutdown_steps)
        }
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

    fn assert_invalid_data(err: io::Error) {
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            err.kind()
        );
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
    fn write_empty_returns_zero() {
        init_test("write_empty_returns_zero");
        let mut output = Vec::new();
        let mut fut = output.write(b"");
        let mut fut = Pin::new(&mut fut);

        let n = poll_ready(&mut fut).unwrap();
        crate::assert_with_log!(n == 0, "bytes written", 0, n);
        crate::assert_with_log!(output.is_empty(), "output empty", true, output.is_empty());
        crate::test_complete!("write_empty_returns_zero");
    }

    #[test]
    fn write_rejects_overreported_writer_progress() {
        init_test("write_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write(b"abc");
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(output.written == b"abc", "written", b"abc", output.written);
        crate::test_complete!("write_rejects_overreported_writer_progress");
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
    fn write_all_empty_returns_without_polling_writer() {
        init_test("write_all_empty_returns_without_polling_writer");
        let mut output = PanicOnUseWriter;
        let mut fut = output.write_all(b"");
        let mut fut = Pin::new(&mut fut);

        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("write_all_empty_returns_without_polling_writer");
    }

    #[test]
    fn write_all_rejects_overreported_writer_progress() {
        init_test("write_all_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write_all(b"abc");
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_all must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(output.written == b"abc", "written", b"abc", output.written);
        crate::test_complete!("write_all_rejects_overreported_writer_progress");
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
    fn write_u8_rejects_overreported_writer_progress() {
        init_test("write_u8_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write_u8(0x42);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_u8 must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(
            output.written == vec![0x42],
            "written",
            vec![0x42],
            output.written
        );
        crate::test_complete!("write_u8_rejects_overreported_writer_progress");
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
    fn write_u16_rejects_overreported_writer_progress() {
        init_test("write_u16_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write_u16(0x0102);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_u16 must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(
            output.written == vec![0x01, 0x02],
            "written",
            vec![0x01, 0x02],
            output.written
        );
        crate::test_complete!("write_u16_rejects_overreported_writer_progress");
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
    fn flush_future_retries_after_pending() {
        init_test("flush_future_retries_after_pending");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = ScriptedControlWriter::new(
            waker.clone(),
            [ControlStep::Pending, ControlStep::ReadyOk],
            [],
        );

        {
            let mut fut = writer.flush();
            let first = Pin::new(&mut fut).poll(&mut cx);
            crate::assert_with_log!(
                matches!(first, Poll::Pending),
                "first flush pending",
                true,
                matches!(first, Poll::Pending)
            );

            let second = Pin::new(&mut fut).poll(&mut cx);
            let ready = matches!(second, Poll::Ready(Ok(())));
            crate::assert_with_log!(ready, "second flush ready", true, ready);
        }

        crate::assert_with_log!(
            writer.flush_polls == 2,
            "flush poll count",
            2,
            writer.flush_polls
        );
        crate::assert_with_log!(
            writer.shutdown_polls == 0,
            "shutdown not polled",
            0,
            writer.shutdown_polls
        );
        crate::assert_with_log!(
            writer.saw_expected_waker,
            "context forwarded",
            true,
            writer.saw_expected_waker
        );
        crate::test_complete!("flush_future_retries_after_pending");
    }

    #[test]
    fn flush_future_error_is_terminal() {
        init_test("flush_future_error_is_terminal");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = ScriptedControlWriter::new(
            waker.clone(),
            [ControlStep::ReadyErr(io::ErrorKind::BrokenPipe)],
            [],
        );

        {
            let mut fut = writer.flush();
            let first = Pin::new(&mut fut).poll(&mut cx);
            let err = match first {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected flush error, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::BrokenPipe,
                "flush error kind",
                io::ErrorKind::BrokenPipe,
                err.kind()
            );

            let second = Pin::new(&mut fut).poll(&mut cx);
            let err = match second {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected post-error completion guard, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::Other,
                "post-error completion guard",
                io::ErrorKind::Other,
                err.kind()
            );
        }

        crate::assert_with_log!(
            writer.flush_polls == 1,
            "flush poll count",
            1,
            writer.flush_polls
        );
        crate::test_complete!("flush_future_error_is_terminal");
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
    fn shutdown_future_is_single_use_after_ready() {
        init_test("shutdown_future_is_single_use_after_ready");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = ScriptedControlWriter::new(waker.clone(), [], [ControlStep::ReadyOk]);

        {
            let mut fut = writer.shutdown();
            let first = Pin::new(&mut fut).poll(&mut cx);
            let ready = matches!(first, Poll::Ready(Ok(())));
            crate::assert_with_log!(ready, "first shutdown ready", true, ready);

            let second = Pin::new(&mut fut).poll(&mut cx);
            let err = match second {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected post-completion error, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::Other,
                "post-completion error kind",
                io::ErrorKind::Other,
                err.kind()
            );
        }

        crate::assert_with_log!(
            writer.shutdown_polls == 1,
            "shutdown poll count",
            1,
            writer.shutdown_polls
        );
        crate::assert_with_log!(
            writer.flush_polls == 0,
            "flush not polled",
            0,
            writer.flush_polls
        );
        crate::test_complete!("shutdown_future_is_single_use_after_ready");
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
    fn write_vectored_empty_returns_zero() {
        init_test("write_vectored_empty_returns_zero");
        let mut output = Vec::new();
        let bufs = &[IoSlice::new(b""), IoSlice::new(b"")];
        let mut fut = output.write_vectored(bufs);
        let mut fut = Pin::new(&mut fut);

        let n = poll_ready(&mut fut).unwrap();
        crate::assert_with_log!(n == 0, "bytes written", 0, n);
        crate::assert_with_log!(output.is_empty(), "output empty", true, output.is_empty());
        crate::test_complete!("write_vectored_empty_returns_zero");
    }

    #[test]
    fn write_vectored_rejects_overreported_writer_progress() {
        init_test("write_vectored_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let data1 = b"hello ";
        let data2 = b"world";
        let bufs = &[IoSlice::new(data1), IoSlice::new(data2)];
        let mut fut = output.write_vectored(bufs);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_vectored must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(
            output.written == b"hello world",
            "written",
            b"hello world",
            output.written
        );
        crate::test_complete!("write_vectored_rejects_overreported_writer_progress");
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
    fn write_all_buf_rejects_overreported_writer_before_advancing_buf() {
        init_test("write_all_buf_rejects_overreported_writer_before_advancing_buf");
        let mut output = OverreportingWriter::new();
        let mut input: &[u8] = b"buffered";
        let mut fut = output.write_all_buf(&mut input);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_all_buf must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(input == b"buffered", "input", b"buffered", input);
        crate::assert_with_log!(
            output.written == b"buffered",
            "written",
            b"buffered",
            output.written
        );
        crate::test_complete!("write_all_buf_rejects_overreported_writer_before_advancing_buf");
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
