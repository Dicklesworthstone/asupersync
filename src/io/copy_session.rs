//! Resumable byte copying with caller-owned read-ahead and progress.
//!
//! [`CopySession::run`] borrows its session. Dropping that future, observing
//! cooperative cancellation, or returning an I/O error leaves unread-ahead bytes
//! and committed-write counters in the session. Calling `run` again resumes at
//! the first byte not yet accepted by the writer. Unlike `copy`, the disposable
//! future owns no transfer buffer. No background task or executor is created.
//!
//! Keep the session alive until completion, or use [`CopySession::into_parts`]
//! to recover BOTH endpoints and pending bytes. Dropping the session itself can
//! discard read-ahead, just like dropping a buffered reader. This is in-process
//! continuation, not a durable checkpoint, replay protocol, remote acknowledgement
//! or rollback of completed writes. After an I/O error, retry only when the
//! endpoint's protocol permits it. A provider panic or an impossible write count
//! poisons the session: unknown side effects must never be silently retried.

use super::{AsyncRead, AsyncWrite, ReadBuf};
use crate::cx::{CancelWakerToken, Cx};
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFAULT_CAPACITY: usize = 8 * 1024;
const POLL_BUDGET: usize = 32;

/// Cumulative observations for one direction, retained across every `run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopySessionProgress {
    /// Bytes returned by the reader, including pending read-ahead.
    pub read: u64,
    /// Bytes accepted by successful writes; not remote or durable acknowledgement.
    pub written: u64,
    /// Read-ahead not yet accepted by the writer.
    pub buffered: usize,
    /// The reader returned a successful zero-byte read into a nonempty buffer.
    pub read_eof: bool,
    /// A flush succeeded after the last successful write.
    pub flushed: bool,
    /// The write direction completed explicit shutdown (duplex sessions only).
    pub write_shutdown: bool,
}

struct Direction {
    buffer: Vec<u8>,
    pos: usize,
    len: usize,
    read: u64,
    written: u64,
    eof: bool,
    flushed: bool,
    shutdown: bool,
    poison: Option<&'static str>,
}

impl Direction {
    fn new(buffer: Vec<u8>) -> Self {
        Self {
            buffer, pos: 0, len: 0, read: 0, written: 0,
            eof: false, flushed: false, shutdown: false, poison: None,
        }
    }

    fn progress(&self) -> CopySessionProgress {
        CopySessionProgress {
            read: self.read, written: self.written, buffered: self.len - self.pos,
            read_eof: self.eof, flushed: self.flushed, write_shutdown: self.shutdown,
        }
    }

    fn complete(&self, shutdown: bool) -> bool {
        self.poison.is_none() && self.eof && self.pos == self.len && self.flushed
            && (!shutdown || self.shutdown)
    }

    fn into_pending(mut self) -> Vec<u8> {
        self.buffer.truncate(self.len);
        drop(self.buffer.drain(..self.pos));
        self.buffer
    }

    fn step<R, W>(
        &mut self, reader: &mut R, writer: &mut W, cx: &mut Context<'_>, shutdown: bool,
    ) -> io::Result<Step>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        if let Some(reason) = self.poison {
            return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
        }
        if self.complete(shutdown) { return Ok(Step::Done); }
        if self.pos < self.len {
            let offered = &self.buffer[self.pos..self.len];
            let result = guarded(&mut self.poison, || Pin::new(&mut *writer).poll_write(cx, offered));
            match result {
                Poll::Pending => return Ok(Step::Pending),
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(0)) => {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "copy session writer made no progress"));
                }
                Poll::Ready(Ok(n)) => {
                    if n > offered.len() {
                        let reason = "copy session writer accepted more bytes than offered";
                        self.poison = Some(reason);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                    }
                    // Read admission below guarantees written <= read <= u64::MAX.
                    self.pos += n;
                    self.written += n as u64;
                    self.flushed = false;
                    return Ok(Step::Progress);
                }
            }
        }
        if self.eof {
            if !self.flushed { return self.flush(writer, cx); }
            if shutdown && !self.shutdown {
                match guarded(&mut self.poison, || Pin::new(writer).poll_shutdown(cx)) {
                    Poll::Pending => return Ok(Step::Pending),
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Ready(Ok(())) => self.shutdown = true,
                }
            }
            return Ok(Step::Done);
        }

        // Never advance the source beyond representable progress. In particular,
        // a zero-sized ReadBuf must not accidentally become a fabricated EOF.
        let available = usize::try_from(u64::MAX - self.read).unwrap_or(usize::MAX);
        let capacity = self.buffer.len().min(available);
        if capacity == 0 {
            return Err(io::Error::other("copy session byte counter exhausted"));
        }
        self.pos = 0;
        self.len = 0;
        let mut buf = ReadBuf::new(&mut self.buffer[..capacity]);
        let result = guarded(&mut self.poison, || Pin::new(reader).poll_read(cx, &mut buf));
        self.len = buf.filled().len();
        self.read += self.len as u64;
        match result {
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => {
                self.eof = self.len == 0;
                Ok(Step::Progress)
            }
            // Preserve any reported bytes even from an unusual reader that fills
            // ReadBuf before returning Pending. Never interpret Pending as EOF.
            Poll::Pending if self.len != 0 => Ok(Step::Progress),
            Poll::Pending if !self.flushed && self.written != 0 => self.flush(writer, cx),
            Poll::Pending => Ok(Step::Pending),
        }
    }

    fn flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self, writer: &mut W, cx: &mut Context<'_>,
    ) -> io::Result<Step> {
        match guarded(&mut self.poison, || Pin::new(writer).poll_flush(cx)) {
            Poll::Pending => Ok(Step::Pending),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => { self.flushed = true; Ok(Step::Progress) }
        }
    }
}

// Mark before calling arbitrary I/O code; an unwind leaves a sticky refusal.
// Do not catch, stringify, drop, or replace the provider's original panic payload.
fn guarded<T>(poison: &mut Option<&'static str>, action: impl FnOnce() -> T) -> T {
    *poison = Some("copy session provider panicked; endpoint effects are unknown");
    let result = action();
    *poison = None;
    result
}

enum Step { Progress, Pending, Done }

fn buffer(capacity: usize) -> io::Result<Vec<u8>> {
    if capacity == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "copy buffer capacity must be nonzero"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(io::Error::other)?;
    bytes.resize(capacity, 0);
    Ok(bytes)
}

struct Cancellation<'a> { cx: &'a Cx, token: Option<CancelWakerToken> }
impl Cancellation<'_> {
    fn register(&mut self, cx: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, cx.waker()));
    }
    fn check(&self) -> io::Result<()> {
        self.cx.checkpoint().map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "copy session cancelled"))
    }
}
impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

/// A byte-copy owner whose read-ahead survives dropping a borrowing run future.
///
/// The endpoints may be owned values or mutable references. No `Clone`, `Sync`,
/// `'static`, runtime spawning, or ambient context is required. A complete run
/// flushes but does not shut down the writer, matching ordinary `copy` semantics.
#[must_use = "retain the session while pending read-ahead must survive cancellation"]
pub struct CopySession<R, W> {
    reader: R,
    writer: W,
    direction: Direction,
}

impl<R, W> fmt::Debug for CopySession<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopySession").field("progress", &self.progress())
            .field("capacity", &self.direction.buffer.len())
            .field("poisoned", &self.direction.poison.is_some()).finish_non_exhaustive()
    }
}

impl<R, W> CopySession<R, W> {
    /// Retain both endpoints and one 8 KiB buffer; performs no I/O.
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer, direction: Direction::new(vec![0; DEFAULT_CAPACITY]) }
    }

    /// Use an explicit positive buffer bound. Refuse allocation failure before I/O.
    pub fn with_capacity(reader: R, writer: W, capacity: usize) -> io::Result<Self> {
        Ok(Self { reader, writer, direction: Direction::new(buffer(capacity)?) })
    }

    /// Cumulative committed progress, including a retained uncommitted suffix.
    #[must_use]
    pub fn progress(&self) -> CopySessionProgress { self.direction.progress() }

    /// Whether EOF and the final flush completed without a poisoned provider.
    #[must_use]
    pub fn is_complete(&self) -> bool { self.direction.complete(false) }

    /// Unwritten bytes retained after the source advanced. Does not consume them.
    #[must_use]
    pub fn pending_bytes(&self) -> &[u8] {
        &self.direction.buffer[self.direction.pos..self.direction.len]
    }

    /// Recover the reader, writer, and unwritten suffix, in that order.
    ///
    /// The reader has ALREADY advanced past the suffix. To continue manually,
    /// write these bytes before reading more. This neither flushes nor shuts down.
    /// Provider panics/invalid counts may have unknown external effects; extracting
    /// endpoints does not make retry safe. The Debug representation omits bytes.
    #[must_use]
    pub fn into_parts(self) -> (R, W, Vec<u8>) {
        (self.reader, self.writer, self.direction.into_pending())
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> CopySession<R, W> {
    /// Drive or resume copying using explicit cancellation authority.
    ///
    /// Returns cumulative accepted-write bytes, not just this invocation's delta.
    /// Cancellation returns Interrupted without draining or discarding read-ahead.
    /// Resume with a live context after the endpoint permits it. I/O errors retain
    /// the original error and progress; automatic retry is deliberately absent.
    /// Completed calls are idempotent and perform no more I/O, even with a
    /// subsequently cancelled context. An active run registers cancellation as a
    /// wake source, so a parked provider need not generate another I/O event.
    /// Each poll makes bounded progress; a single blocking provider poll cannot
    /// be preempted. Drop the run future, NOT the session, to pause without loss.
    pub async fn run(&mut self, cx: &Cx) -> io::Result<u64> {
        let mut cancellation = Cancellation { cx, token: None };
        poll_fn(|task_cx| {
            if self.is_complete() { return Poll::Ready(Ok(self.direction.written)); }
            cancellation.register(task_cx);
            for _ in 0..POLL_BUDGET {
                if let Err(error) = cancellation.check() { return Poll::Ready(Err(error)); }
                match self.direction.step(&mut self.reader, &mut self.writer, task_cx, false) {
                    Ok(Step::Done) => return Poll::Ready(Ok(self.direction.written)),
                    Ok(Step::Pending) => return Poll::Pending,
                    Ok(Step::Progress) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            task_cx.waker().wake_by_ref();
            Poll::Pending
        }).await
    }
}

#[cfg(test)]
mod tests;
