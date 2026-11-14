//! Resumable exact I/O with caller-retained buffers and progress.
//!
//! Dropping a borrowing `run` future pauses a session, not its byte accounting.
//! Retain the session until completion or recover its endpoint, buffer and
//! offset with `into_parts`. These are in-process continuation primitives, not
//! transactions: completed I/O cannot be rolled back and remote delivery is not
//! acknowledged. Retry after an I/O error only when the endpoint permits it.
//!
//! Cooperative cancellation returns [`io::ErrorKind::Interrupted`]. Callers
//! with a retry loop on `Interrupted` must check [`Cx::is_cancel_requested`] to
//! distinguish cancellation from an endpoint-level interruption (such as POSIX
//! `EINTR`); retrying on a cancelled context will spin without making progress.

use super::{AsyncRead, ReadBuf};
use crate::cx::{CancelWakerToken, Cx};
use crate::types::Time;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const POLL_BUDGET: usize = 32;
const POISONED: &str = "exact I/O provider panicked; endpoint effects are unknown";
const REPLACED_BUFFER: &str =
    "exact I/O reader replaced the read buffer it was given; endpoint effects are unknown";

/// Whether a reader left its fill in the buffer it was handed: no longer than
/// the `offered` bytes and starting at `start`. `ReadBuf` is covariant in its
/// lifetime, so a reader can swap in a buffer over other memory; counting that
/// fill would record bytes the destination never received. An empty fill moves
/// nothing, wherever it points.
pub(crate) fn filled_in_place(filled: &[u8], start: *const u8, offered: usize) -> bool {
    filled.is_empty() || (filled.len() <= offered && std::ptr::eq(filled.as_ptr(), start))
}

struct Cancellation<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl Cancellation<'_> {
    fn register(&mut self, task_cx: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, task_cx.waker()));
    }

    fn check(&self) -> io::Result<()> {
        self.cx
            .checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "exact I/O session cancelled"))
    }
}

impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

/// One owner-clock boundary shared by all resumable I/O sessions. The run
/// future borrows its session, so retiring this boundary never discards the
/// session's buffers, progress, or half-close state.
pub(super) async fn run_with_deadline<T>(
    cx: &Cx,
    deadline: Time,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut operation = std::pin::pin!(operation);
    let mut cancellation = Cancellation { cx, token: None };
    loop {
        let now = cx.now();
        cancellation.check()?;
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "I/O session deadline elapsed",
            ));
        }

        // An owner budget needs its own wake even when this future is polled
        // by a different context. Once that budget expires under a mask, use
        // the explicit deadline instead of repeatedly polling a ready timer.
        let wake_at = cx
            .budget()
            .deadline
            .filter(|owner_deadline| *owner_deadline > now)
            .map_or(deadline, |owner_deadline| deadline.min(owner_deadline));
        let mut timer = std::pin::pin!(cx.sleep_until_on_clock(wake_at));
        let result = poll_fn(|task| {
            // Retain this registration through masked requests: unmasking
            // must still wake a parked run owned by a foreign context.
            cancellation.register(task);
            if let Err(error) = cancellation.check() {
                return Poll::Ready(Some(Err(error)));
            }
            if timer.as_mut().poll_deadline(task).is_ready() {
                return Poll::Ready(None);
            }
            // Preserve a ready provider result, including its original error,
            // even if synchronous provider work crossed the deadline.
            operation.as_mut().poll(task).map(Some)
        })
        .await;
        if let Some(result) = result {
            return result;
        }
    }
}

/// An exact read whose initialized prefix survives cancellation and future drop.
///
/// The reader may be owned or borrowed. The session exclusively borrows a fixed
/// destination slice, so neither the buffer nor its resume offset can accidentally
/// change between runs. No allocation, worker, `Clone` bound or ambient runtime
/// is required. Existing `AsyncReadExt::read_exact` behavior is unchanged.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) -> std::io::Result<()> {
/// use asupersync::io::ReadExactSession;
/// let mut source: &[u8] = b"headerpayload";
/// let mut header = [0; 6];
/// let mut session = ReadExactSession::new(&mut source, &mut header);
/// session.run(cx).await?;
/// assert_eq!(session.filled(), b"header");
/// // A dropped run could instead be retried on the SAME session.
/// # Ok(())
/// # }
/// ```
#[must_use = "retain the session to preserve exact-read progress"]
pub struct ReadExactSession<'a, R> {
    reader: R,
    buffer: &'a mut [u8],
    pos: usize,
    poison: Option<&'static str>,
}

impl<R> fmt::Debug for ReadExactSession<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadExactSession")
            .field("read", &self.pos)
            .field("length", &self.buffer.len())
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl<'a, R> ReadExactSession<'a, R> {
    /// Retain the reader and destination; performs no I/O and allocates nothing.
    pub fn new(reader: R, buffer: &'a mut [u8]) -> Self {
        Self {
            reader,
            buffer,
            pos: 0,
            poison: None,
        }
    }

    /// Bytes reported filled by the reader across all runs.
    #[must_use]
    pub fn bytes_read(&self) -> usize {
        self.pos
    }

    /// The initialized prefix already consumed from the reader.
    ///
    /// A provider panic may have unreported effects beyond this prefix. See
    /// [`Self::is_poisoned`] before deciding whether manual recovery is possible.
    #[must_use]
    pub fn filled(&self) -> &[u8] {
        &self.buffer[..self.pos]
    }

    /// Bytes still needed to fill the destination.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.pos
    }

    /// Whether the destination is full and the provider has not been poisoned.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.poison.is_none() && self.pos == self.buffer.len()
    }

    /// Whether ambiguous provider effects prohibit automatic continuation.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_some()
    }

    /// Recover the advanced reader, complete destination and filled-prefix length.
    ///
    /// Continue into `buffer[read..]`, not the beginning of the buffer. This does
    /// not rewind the reader or make a poisoned endpoint safe to retry.
    #[must_use]
    pub fn into_parts(self) -> (R, &'a mut [u8], usize) {
        (self.reader, self.buffer, self.pos)
    }
}

impl<R: AsyncRead + Unpin> ReadExactSession<'_, R> {
    /// Fill or resume the destination before an absolute owner-clock deadline.
    ///
    /// The deadline covers this entire run and is not extended by partial
    /// progress. An active run returns `TimedOut` on explicit expiry, or
    /// `Interrupted` when `cx` acknowledges cancellation, including an earlier
    /// owner budget. The supplied context provides the clock and cancellation
    /// authority even when another context polls the future.
    ///
    /// Cancellation masks defer owner cancellation, but not the explicit
    /// deadline. An already-complete session returns its cached count without
    /// checking either boundary or polling the reader. Otherwise cancellation
    /// and expiry are checked before each poll of [`Self::run`]. A ready I/O
    /// result retains its original value, including errors, if synchronous
    /// provider work crosses the deadline during that poll; such work cannot
    /// be preempted.
    ///
    /// Expiry, cancellation, and dropping this future retain the filled prefix
    /// in the session. Resume this same session with [`Self::run`] or a later
    /// deadline and a live context. No timer or cancellation registration owned
    /// by this run remains after it completes or is dropped.
    pub async fn run_until(&mut self, cx: &Cx, deadline: Time) -> io::Result<usize> {
        if self.is_complete() {
            return self.run(cx).await;
        }
        run_with_deadline(cx, deadline, self.run(cx)).await
    }

    /// Fill the remaining suffix, returning the cumulative filled-prefix length.
    ///
    /// Dropping this future retains all reported bytes and the resume offset in
    /// the session. Cooperative cancellation returns `Interrupted`, including
    /// when the reader is parked; a new live context can resume the session.
    /// Callers retrying on `ErrorKind::Interrupted` should check
    /// `cx.is_cancel_requested()` to distinguish cooperative cancellation from
    /// an endpoint-level `EINTR`: retrying on a cancelled context will spin
    /// without making progress.
    /// A zero-byte successful read before completion returns `UnexpectedEof`.
    /// Other I/O errors are returned unchanged, with reported progress retained.
    ///
    /// Completed runs are idempotent, even with a subsequently cancelled context.
    /// Each poll permits at most 32 reader polls. A provider panic propagates
    /// unchanged and poisons future runs rather than risking duplicate consumption.
    /// No guarantee can undo unreported provider side effects or preempt a
    /// blocking provider poll.
    pub async fn run(&mut self, cx: &Cx) -> io::Result<usize> {
        let mut cancellation = Cancellation { cx, token: None };
        poll_fn(|task_cx| {
            if let Some(reason) = self.poison {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)));
            }
            if self.is_complete() {
                return Poll::Ready(Ok(self.pos));
            }
            cancellation.register(task_cx);
            for _ in 0..POLL_BUDGET {
                if let Err(error) = cancellation.check() {
                    return Poll::Ready(Err(error));
                }
                let offered = self.buffer.len() - self.pos;
                let start = self.buffer[self.pos..].as_ptr();
                let mut buffer = ReadBuf::new(&mut self.buffer[self.pos..]);
                self.poison = Some(POISONED);
                let result = Pin::new(&mut self.reader).poll_read(task_cx, &mut buffer);
                // A reader can replace the ReadBuf it was handed with one over
                // other memory; bytes it filled there never reached this
                // destination, and what it took from its source is unknown
                // (br-asupersync-qop6q8).
                if !filled_in_place(buffer.filled(), start, offered) {
                    self.poison = Some(REPLACED_BUFFER);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        REPLACED_BUFFER,
                    )));
                }
                self.poison = None;
                // Record before every return, including unusual providers that
                // append bytes before returning Pending or an I/O error.
                let read = buffer.filled().len();
                self.pos += read;
                match result {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if read == 0 => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    Poll::Pending if read == 0 => return Poll::Pending,
                    Poll::Pending | Poll::Ready(Ok(())) => {}
                }
                if self.is_complete() {
                    return Poll::Ready(Ok(self.pos));
                }
            }
            task_cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }
}

mod write;
pub use write::WriteAllSession;

mod vectored;
pub use vectored::WriteAllVectoredSession;

mod read_vectored;
pub use read_vectored::ReadExactVectoredSession;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod deadline_tests;
