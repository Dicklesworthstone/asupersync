//! Resumable exact I/O with caller-retained buffers and progress.
//!
//! Dropping a borrowing `run` future pauses a session, not its byte accounting.
//! Retain the session until completion or recover its endpoint, buffer and
//! offset with `into_parts`. These are in-process continuation primitives, not
//! transactions: completed I/O cannot be rolled back and remote delivery is not
//! acknowledged. Retry after an I/O error only when the endpoint permits it.

use super::{AsyncRead, ReadBuf};
use crate::cx::{CancelWakerToken, Cx};
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const POLL_BUDGET: usize = 32;
const POISONED: &str = "exact I/O provider panicked; endpoint effects are unknown";

struct Cancellation<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl Cancellation<'_> {
    fn register(&mut self, task_cx: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, task_cx.waker()));
    }

    fn check(&self) -> io::Result<()> {
        self.cx.checkpoint().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "exact I/O session cancelled")
        })
    }
}

impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
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
        Self { reader, buffer, pos: 0, poison: None }
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
    /// Fill the remaining suffix, returning the cumulative filled-prefix length.
    ///
    /// Dropping this future retains all reported bytes and the resume offset in
    /// the session. Cooperative cancellation returns `Interrupted`, including
    /// when the reader is parked; a new live context can resume the session.
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
                let mut buffer = ReadBuf::new(&mut self.buffer[self.pos..]);
                self.poison = Some(POISONED);
                let result = Pin::new(&mut self.reader).poll_read(task_cx, &mut buffer);
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
        }).await
    }
}

mod write;
pub use write::WriteAllSession;

#[cfg(test)]
mod tests;
