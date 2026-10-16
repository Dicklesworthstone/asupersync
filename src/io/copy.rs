//! Async copy operations between readers and writers.
//!
//! This module provides efficient async copy operations with progress tracking.
//!
//! # Cancel Safety
//!
//! - [`Copy`]: **Not drop-cancel-safe.** Dropping after a successful read but
//!   before the corresponding write discards private read-ahead.
//! - [`CopyBuf`]: Drop-cancel-safe. The caller-owned reader buffer is consumed
//!   only after the corresponding write commits.
//! - [`CopyWithProgress`]: **Not drop-cancel-safe.** Its byte count is accurate
//!   for committed writes, but private read-ahead is lost on drop.
//! - [`CopyBidirectional`]: **Not drop-cancel-safe.** Either direction can lose
//!   up to one private buffer of read-ahead on drop.
//!
//! Cooperative `Cx` cancellation is a separate boundary: the unbuffered
//! futures make a bounded best-effort attempt to drain private read-ahead when
//! they are polled after cancellation. A race/select that drops the future
//! without another poll cannot run that drain.
//!
//! Cooperative cancellation returns [`std::io::ErrorKind::Interrupted`].
//! Callers with a retry loop on `Interrupted` must check whether context
//! cancellation was requested (e.g. via `cx.is_cancel_requested()`), as
//! retrying while cancelled will immediately fail again without yielding.

use super::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer size for copy operations.
const DEFAULT_BUF_SIZE: usize = 8192;

/// Maximum number of best-effort `poll_write` attempts when draining a
/// buffered prefix on cancellation. Bounded so a destination that's
/// permanently `Pending` cannot stall the cancel path. A typical
/// kernel socket buffer drain takes one or two non-blocking writes;
/// four attempts is comfortable headroom. (br-asupersync-8ww5b0)
const MAX_DRAIN_ATTEMPTS_ON_CANCEL: u8 = 4;

/// Best-effort drain of `buf[*pos..cap]` to `writer` when the surrounding
/// future has been cancelled.
///
/// Returns the number of bytes successfully drained. The caller advances
/// its `total` counter by this amount before returning `Err(Interrupted)`,
/// so the post-cancel `total` accurately reflects everything that
/// reached the destination — not just the bytes already written before
/// the cancel-check fired.
///
/// Per AGENTS.md cancellation protocol (request → drain → finalize),
/// the buffered prefix must be flushed BEFORE the future returns an
/// error. We can't `.await`, so the drain is bounded:
///
///   * Up to `MAX_DRAIN_ATTEMPTS_ON_CANCEL` non-blocking `poll_write`
///     calls per drain. A single call may write less than the full
///     remaining window, so a small loop is necessary.
///   * `Poll::Pending`, `Ok(0)`, or `Err(_)` from `poll_write`
///     terminates the loop. Any unwritten bytes are dropped — by
///     design: the future is cancelled, we cannot honor further
///     async progress. The cancel error supersedes the write error.
///
/// (br-asupersync-8ww5b0)
fn drain_on_cancel<W>(
    writer: &mut W,
    buf: &[u8],
    pos: &mut usize,
    cap: usize,
    cx: &mut Context<'_>,
) -> u64
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut drained = 0u64;
    let mut attempts = 0u8;
    while *pos < cap && attempts < MAX_DRAIN_ATTEMPTS_ON_CANCEL {
        attempts += 1;
        match Pin::new(&mut *writer).poll_write(cx, &buf[*pos..cap]) {
            Poll::Pending | Poll::Ready(Err(_) | Ok(0)) => break,
            Poll::Ready(Ok(n)) => {
                let remaining = cap - *pos;
                let advanced = n.min(remaining);
                *pos += advanced;
                drained += advanced as u64;
                if n > remaining {
                    break;
                }
            }
        }
    }
    drained
}

/// Poll into owned copy storage without trusting a substituted `ReadBuf`.
///
/// A reader can replace the covariant buffer with one over other memory. Its
/// filled length must not become a cursor into our unchanged storage. Also
/// retain progress from providers that fill in place before returning Pending:
/// discarding those bytes would advance the source without advancing the copy.
fn poll_read_checked<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut [u8],
) -> Poll<io::Result<usize>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let start = buffer.as_ptr();
    let offered = buffer.len();
    let mut read_buf = ReadBuf::new(buffer);
    let result = Pin::new(reader).poll_read(cx, &mut read_buf);
    let filled = read_buf.filled();
    if !super::transfer_session::filled_in_place(filled, start, offered) {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "copy reader replaced the read buffer it was given; endpoint effects are unknown",
        )));
    }

    match result {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Pending if filled.is_empty() => Poll::Pending,
        Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(filled.len())),
    }
}

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

/// Copy all data from a reader to a writer.
///
/// Returns the total number of bytes copied.
///
/// # Cancel Safety
///
/// This future is **not drop-cancel-safe**. Bytes already written to the
/// writer remain committed, but dropping the future after `reader` advanced
/// and while `writer` is pending discards up to 8192 bytes of
/// private read-ahead. Restarting with the same reader then skips those bytes.
///
/// Use [`copy_buf`] with a caller-owned [`AsyncBufRead`] when future-drop
/// recovery is required. If cooperative `Cx` cancellation is observed on a
/// later poll, this future makes a bounded best-effort drain before returning
/// `Interrupted`; that does not make arbitrary future drop safe.
///
/// # Example
///
/// ```ignore
/// let mut reader: &[u8] = b"hello world";
/// let mut writer = Vec::new();
/// let n = copy(&mut reader, &mut writer).await?;
/// assert_eq!(n, 11);
/// assert_eq!(writer, b"hello world");
/// ```
#[inline]
pub fn copy<'a, R, W>(reader: &'a mut R, writer: &'a mut W) -> Copy<'a, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    Copy {
        reader,
        writer,
        buf: [0u8; DEFAULT_BUF_SIZE],
        read_done: false,
        need_flush: false,
        pos: 0,
        cap: 0,
        total: 0,
        completed: false,
    }
}

/// Future for the [`copy`] function.
pub struct Copy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    buf: [u8; DEFAULT_BUF_SIZE],
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    total: u64,
    completed: bool,
}

impl<R, W> Future for Copy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(Err(io::Error::other("Copy future polled after completion")));
        }

        let mut steps = 0;

        loop {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                // br-asupersync-8ww5b0: best-effort drain of the buffered
                // prefix BEFORE returning Err. Without this, bytes already
                // pulled from `reader` but not yet pushed to `writer` are
                // silently dropped on cancel.
                if this.pos < this.cap {
                    let drained =
                        drain_on_cancel(&mut *this.writer, &this.buf, &mut this.pos, this.cap, cx);
                    this.total += drained;
                }
                this.completed = true;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            // If we have buffered data, write it
            if this.pos < this.cap {
                match Pin::new(&mut *this.writer).poll_write(cx, &this.buf[this.pos..this.cap]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.completed = true;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(n)) => {
                        let remaining = this.cap - this.pos;
                        let n = match checked_write_progress(n, remaining) {
                            Ok(n) => n,
                            Err(err) => {
                                this.completed = true;
                                return Poll::Ready(Err(err));
                            }
                        };
                        this.pos += n;
                        this.total += n as u64;
                        this.need_flush = true;
                        continue;
                    }
                }
            }

            // If read is done and buffer is empty, we're finished
            if this.read_done {
                match Pin::new(&mut *this.writer).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.completed = true;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {
                        this.completed = true;
                        return Poll::Ready(Ok(this.total));
                    }
                }
            }

            // Read more data
            match poll_read_checked(&mut *this.reader, cx, &mut this.buf) {
                Poll::Pending => {
                    if this.need_flush {
                        match Pin::new(&mut *this.writer).poll_flush(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(err)) => {
                                this.completed = true;
                                return Poll::Ready(Err(err));
                            }
                            Poll::Ready(Ok(())) => {
                                this.need_flush = false;
                            }
                        }
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        this.read_done = true;
                    } else {
                        this.pos = 0;
                        this.cap = n;
                    }
                }
            }
        }
    }
}

/// Buffered read trait for efficient copy operations.
///
/// This is a minimal version of `BufRead` for async contexts.
pub trait AsyncBufRead: AsyncRead {
    /// Returns the contents of the internal buffer, filling it if empty.
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>>;

    /// Tells the buffer that `amt` bytes have been consumed.
    fn consume(self: Pin<&mut Self>, amt: usize);
}

impl AsyncBufRead for &[u8] {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Poll::Ready(Ok(this))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        let to_consume = std::cmp::min(amt, this.len());
        *this = &this[to_consume..];
    }
}

impl<T> AsyncBufRead for std::io::Cursor<T>
where
    T: AsRef<[u8]> + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        let data = this.get_ref().as_ref();
        let pos = usize::try_from(this.position()).unwrap_or(usize::MAX);
        let start = std::cmp::min(pos, data.len());
        Poll::Ready(Ok(&data[start..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        let data_len = this.get_ref().as_ref().len() as u64;
        let pos = this.position();
        let advance = std::cmp::min(amt as u64, data_len.saturating_sub(pos));
        this.set_position(pos.saturating_add(advance));
    }
}

/// Copy all data from a buffered reader to a writer.
///
/// More efficient than [`copy`] when the reader is already buffered.
///
/// # Cancel Safety
///
/// This future is drop-cancel-safe. It calls [`AsyncBufRead::consume`] only
/// after the corresponding write commits. If the writer is pending and this
/// future is dropped, the uncommitted bytes remain in the caller-owned reader
/// buffer and a new `copy_buf` future can resume without skipping them.
#[inline]
pub fn copy_buf<'a, R, W>(reader: &'a mut R, writer: &'a mut W) -> CopyBuf<'a, R, W>
where
    R: AsyncBufRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    CopyBuf {
        reader,
        writer,
        total: 0,
        read_done: false,
        need_flush: false,
        completed: false,
    }
}

/// Future for the [`copy_buf`] function.
pub struct CopyBuf<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    total: u64,
    read_done: bool,
    need_flush: bool,
    completed: bool,
}

impl<R, W> Future for CopyBuf<'_, R, W>
where
    R: AsyncBufRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "CopyBuf future polled after completion",
            )));
        }

        let mut steps = 0;

        loop {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                this.completed = true;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            if this.read_done {
                match Pin::new(&mut *this.writer).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.completed = true;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {
                        this.completed = true;
                        return Poll::Ready(Ok(this.total));
                    }
                }
            }

            let buf = match Pin::new(&mut *this.reader).poll_fill_buf(cx) {
                Poll::Pending => {
                    if this.need_flush {
                        match Pin::new(&mut *this.writer).poll_flush(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => {
                                this.completed = true;
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                this.need_flush = false;
                            }
                        }
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(buf)) => buf,
            };

            if buf.is_empty() {
                this.read_done = true;
                continue;
            }

            let n = match Pin::new(&mut *this.writer).poll_write(cx, buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(n)) => n,
            };

            let n = match checked_write_progress(n, buf.len()) {
                Ok(n) => n,
                Err(err) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
            };

            Pin::new(&mut *this.reader).consume(n);
            this.total += n as u64;
            this.need_flush = true;
        }
    }
}

/// Copy all data from a reader to a writer with progress reporting.
///
/// The callback `on_progress` is called after each successful write with
/// the cumulative total bytes written so far.
///
/// # Cancel Safety
///
/// This future is **not drop-cancel-safe**. The callback accurately reports
/// committed writes, but dropping after a successful read and before its write
/// completes discards private read-ahead that was never reported. Use
/// [`copy_buf`] when restart-without-skips is required.
///
/// Cooperative `Cx` cancellation observed on a later poll performs the same
/// bounded best-effort drain as [`copy`].
///
/// # Example
///
/// ```ignore
/// let mut reader: &[u8] = b"hello world";
/// let mut writer = Vec::new();
/// let n = copy_with_progress(&mut reader, &mut writer, |total| {
///     println!("Copied {} bytes", total);
/// }).await?;
/// ```
#[inline]
pub fn copy_with_progress<'a, R, W, F>(
    reader: &'a mut R,
    writer: &'a mut W,
    on_progress: F,
) -> CopyWithProgress<'a, R, W, F>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    F: FnMut(u64),
{
    CopyWithProgress {
        reader,
        writer,
        on_progress,
        buf: [0u8; DEFAULT_BUF_SIZE],
        read_done: false,
        need_flush: false,
        pos: 0,
        cap: 0,
        total: 0,
        completed: false,
    }
}

/// Future for the [`copy_with_progress`] function.
pub struct CopyWithProgress<'a, R: ?Sized, W: ?Sized, F> {
    reader: &'a mut R,
    writer: &'a mut W,
    on_progress: F,
    buf: [u8; DEFAULT_BUF_SIZE],
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    total: u64,
    completed: bool,
}

impl<R, W, F> Future for CopyWithProgress<'_, R, W, F>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    F: FnMut(u64) + Unpin,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "CopyWithProgress future polled after completion",
            )));
        }

        let mut steps = 0;

        loop {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                // br-asupersync-8ww5b0: best-effort drain of the buffered
                // prefix on cancel. Progress callback fires for the drained
                // bytes so the caller's progress accounting matches `total`.
                if this.pos < this.cap {
                    let drained =
                        drain_on_cancel(&mut *this.writer, &this.buf, &mut this.pos, this.cap, cx);
                    if drained > 0 {
                        this.total += drained;
                        (this.on_progress)(this.total);
                    }
                }
                this.completed = true;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            // If we have buffered data, write it
            if this.pos < this.cap {
                match Pin::new(&mut *this.writer).poll_write(cx, &this.buf[this.pos..this.cap]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.completed = true;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(n)) => {
                        let remaining = this.cap - this.pos;
                        let n = match checked_write_progress(n, remaining) {
                            Ok(n) => n,
                            Err(err) => {
                                this.completed = true;
                                return Poll::Ready(Err(err));
                            }
                        };
                        this.pos += n;
                        this.total += n as u64;
                        (this.on_progress)(this.total);
                        this.need_flush = true;
                        continue;
                    }
                }
            }

            // If read is done and buffer is empty, we're finished
            if this.read_done {
                match Pin::new(&mut *this.writer).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.completed = true;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {
                        this.completed = true;
                        return Poll::Ready(Ok(this.total));
                    }
                }
            }

            // Read more data
            match poll_read_checked(&mut *this.reader, cx, &mut this.buf) {
                Poll::Pending => {
                    if this.need_flush {
                        match Pin::new(&mut *this.writer).poll_flush(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(err)) => {
                                this.completed = true;
                                return Poll::Ready(Err(err));
                            }
                            Poll::Ready(Ok(())) => {
                                this.need_flush = false;
                            }
                        }
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    this.completed = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        this.read_done = true;
                    } else {
                        this.pos = 0;
                        this.cap = n;
                    }
                }
            }
        }
    }
}

/// Bidirectional copy between two streams.
///
/// Copies data in both directions simultaneously:
/// - From `a` to `b`
/// - From `b` to `a`
///
/// Returns the number of bytes copied in each direction: `(a_to_b, b_to_a)`.
///
/// This is useful for proxying, tunneling, and other bidirectional protocols.
///
/// # Cancel Safety
///
/// This future is **not drop-cancel-safe**. Each direction owns a private
/// 8192-byte read-ahead buffer. Dropping while either peer's
/// writer is pending discards that direction's uncommitted read-ahead, so
/// restarting with the same streams can skip bytes in one or both directions.
/// Returned byte counts still reflect only successful writes.
///
/// Cooperative `Cx` cancellation observed on a later poll makes a bounded
/// best-effort attempt to drain both private buffers before returning
/// `Interrupted`; arbitrary future drop cannot do so.
///
/// # Example
///
/// ```ignore
/// let (a_to_b, b_to_a) = copy_bidirectional(&mut stream_a, &mut stream_b).await?;
/// println!("A->B: {} bytes, B->A: {} bytes", a_to_b, b_to_a);
/// ```
#[inline]
pub fn copy_bidirectional<'a, A, B>(a: &'a mut A, b: &'a mut B) -> CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b_buf: [0u8; DEFAULT_BUF_SIZE],
        b_to_a_buf: [0u8; DEFAULT_BUF_SIZE],
        a_to_b: TransferState::default(),
        b_to_a: TransferState::default(),
        a_to_b_total: 0,
        b_to_a_total: 0,
        completed: false,
    }
}

/// State for one direction of bidirectional copy.
#[derive(Default)]
struct TransferState {
    read_done: bool,
    shutdown_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
}

/// Future for the [`copy_bidirectional`] function.
pub struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b_buf: [u8; DEFAULT_BUF_SIZE],
    b_to_a_buf: [u8; DEFAULT_BUF_SIZE],
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_total: u64,
    b_to_a_total: u64,
    completed: bool,
}

const YIELD_BUDGET: usize = 64;

/// Result of a single transfer step.
enum TransferResult {
    /// Direction is fully complete (read done, buffer flushed, shutdown done).
    Done,
    /// Blocked on I/O.
    Pending,
    /// Made progress (read or wrote bytes, or shutdown).
    Progress,
    /// Encountered an error.
    Error(io::Error),
}

impl<A, B> CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    /// Perform one step of A->B transfer.
    fn step_a_to_b(&mut self, cx: &mut Context<'_>) -> TransferResult {
        let state = &mut self.a_to_b;

        // 1. Try to write buffered data to B
        if state.pos < state.cap {
            match Pin::new(&mut *self.b).poll_write(cx, &self.a_to_b_buf[state.pos..state.cap]) {
                Poll::Pending => return TransferResult::Pending,
                Poll::Ready(Err(err)) => return TransferResult::Error(err),
                Poll::Ready(Ok(n)) => {
                    let remaining = state.cap - state.pos;
                    let n = match checked_write_progress(n, remaining) {
                        Ok(n) => n,
                        Err(err) => return TransferResult::Error(err),
                    };
                    state.pos += n;
                    self.a_to_b_total += n as u64;
                    state.need_flush = true;
                    return TransferResult::Progress;
                }
            }
        }

        // 2. If read from A is done and buffer is empty, flush B, shutdown B and finish
        if state.read_done {
            if state.need_flush {
                match Pin::new(&mut *self.b).poll_flush(cx) {
                    Poll::Pending => return TransferResult::Pending,
                    Poll::Ready(Err(err)) => return TransferResult::Error(err),
                    Poll::Ready(Ok(())) => {
                        state.need_flush = false;
                        return TransferResult::Progress;
                    }
                }
            }
            if !state.shutdown_done {
                match Pin::new(&mut *self.b).poll_shutdown(cx) {
                    Poll::Pending => return TransferResult::Pending,
                    Poll::Ready(Err(err)) => return TransferResult::Error(err),
                    Poll::Ready(Ok(())) => {
                        state.shutdown_done = true;
                        return TransferResult::Progress;
                    }
                }
            }
            return TransferResult::Done;
        }

        // 3. Read more data from A
        // Reset buffer state if empty (it should be empty here due to check 1)
        state.pos = 0;
        state.cap = 0;

        match poll_read_checked(&mut *self.a, cx, &mut self.a_to_b_buf) {
            Poll::Pending => {
                if state.need_flush {
                    match Pin::new(&mut *self.b).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            state.need_flush = false;
                            TransferResult::Progress
                        }
                        Poll::Ready(Err(e)) => TransferResult::Error(e),
                        Poll::Pending => TransferResult::Pending,
                    }
                } else {
                    TransferResult::Pending
                }
            }
            Poll::Ready(Err(err)) => TransferResult::Error(err),
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    state.read_done = true;
                }
                state.cap = n;
                // We just learned we are done (or read data).
                // If done, next call will hit check 2 (buffer empty + read_done).
                TransferResult::Progress
            }
        }
    }

    /// Perform one step of B->A transfer.
    fn step_b_to_a(&mut self, cx: &mut Context<'_>) -> TransferResult {
        let state = &mut self.b_to_a;

        // 1. Try to write buffered data to A
        if state.pos < state.cap {
            match Pin::new(&mut *self.a).poll_write(cx, &self.b_to_a_buf[state.pos..state.cap]) {
                Poll::Pending => return TransferResult::Pending,
                Poll::Ready(Err(err)) => return TransferResult::Error(err),
                Poll::Ready(Ok(n)) => {
                    let remaining = state.cap - state.pos;
                    let n = match checked_write_progress(n, remaining) {
                        Ok(n) => n,
                        Err(err) => return TransferResult::Error(err),
                    };
                    state.pos += n;
                    self.b_to_a_total += n as u64;
                    state.need_flush = true;
                    return TransferResult::Progress;
                }
            }
        }

        // 2. If read from B is done and buffer is empty, flush A, shutdown A and finish
        if state.read_done {
            if state.need_flush {
                match Pin::new(&mut *self.a).poll_flush(cx) {
                    Poll::Pending => return TransferResult::Pending,
                    Poll::Ready(Err(err)) => return TransferResult::Error(err),
                    Poll::Ready(Ok(())) => {
                        state.need_flush = false;
                        return TransferResult::Progress;
                    }
                }
            }
            if !state.shutdown_done {
                match Pin::new(&mut *self.a).poll_shutdown(cx) {
                    Poll::Pending => return TransferResult::Pending,
                    Poll::Ready(Err(err)) => return TransferResult::Error(err),
                    Poll::Ready(Ok(())) => {
                        state.shutdown_done = true;
                        return TransferResult::Progress;
                    }
                }
            }
            return TransferResult::Done;
        }

        // 3. Read more data from B
        state.pos = 0;
        state.cap = 0;

        match poll_read_checked(&mut *self.b, cx, &mut self.b_to_a_buf) {
            Poll::Pending => {
                if state.need_flush {
                    match Pin::new(&mut *self.a).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            state.need_flush = false;
                            TransferResult::Progress
                        }
                        Poll::Ready(Err(e)) => TransferResult::Error(e),
                        Poll::Pending => TransferResult::Pending,
                    }
                } else {
                    TransferResult::Pending
                }
            }
            Poll::Ready(Err(err)) => TransferResult::Error(err),
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    state.read_done = true;
                }
                state.cap = n;
                TransferResult::Progress
            }
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "CopyBidirectional future polled after completion",
            )));
        }

        let mut steps = 0;

        // Poll both directions, interleaved, until both block or are done
        loop {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                // br-asupersync-8ww5b0: drain both per-direction buffered
                // prefixes BEFORE returning Err. A->B drains to writer `b`,
                // B->A drains to writer `a`. Each direction is independent
                // and best-effort.
                if this.a_to_b.pos < this.a_to_b.cap {
                    let drained = drain_on_cancel(
                        &mut *this.b,
                        &this.a_to_b_buf,
                        &mut this.a_to_b.pos,
                        this.a_to_b.cap,
                        cx,
                    );
                    this.a_to_b_total += drained;
                }
                if this.b_to_a.pos < this.b_to_a.cap {
                    let drained = drain_on_cancel(
                        &mut *this.a,
                        &this.b_to_a_buf,
                        &mut this.b_to_a.pos,
                        this.b_to_a.cap,
                        cx,
                    );
                    this.b_to_a_total += drained;
                }
                this.completed = true;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            // Check yield budget to prevent starvation
            if steps >= YIELD_BUDGET {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            let mut made_progress = false;

            // Step A->B
            match this.step_a_to_b(cx) {
                TransferResult::Progress => made_progress = true,
                TransferResult::Error(e) => {
                    this.completed = true;
                    return Poll::Ready(Err(e));
                }
                TransferResult::Done | TransferResult::Pending => {}
            }

            // Step B->A
            match this.step_b_to_a(cx) {
                TransferResult::Progress => made_progress = true,
                TransferResult::Error(e) => {
                    this.completed = true;
                    return Poll::Ready(Err(e));
                }
                TransferResult::Done | TransferResult::Pending => {}
            }

            if made_progress {
                steps += 1;
            } else {
                // Check if both are done (read complete, buffer flushed, AND shutdown complete)
                let a_to_b_done = this.a_to_b.read_done
                    && this.a_to_b.pos >= this.a_to_b.cap
                    && this.a_to_b.shutdown_done;
                let b_to_a_done = this.b_to_a.read_done
                    && this.b_to_a.pos >= this.b_to_a.cap
                    && this.b_to_a.shutdown_done;

                if a_to_b_done && b_to_a_done {
                    this.completed = true;
                    return Poll::Ready(Ok((this.a_to_b_total, this.b_to_a_total)));
                }
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
#[path = "copy_inline_tests.rs"]
mod tests;
