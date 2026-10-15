use super::{Cancellation, POISONED, POLL_BUDGET};
use crate::cx::Cx;
use crate::io::AsyncWrite;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

/// A complete write whose accepted-byte offset survives future drop.
///
/// The session retains the writer and an immutable source slice. A new `run`
/// resumes at the first byte not yet accepted by `poll_write`; it never resends
/// the accepted prefix. Keep the session alive across select/race cancellation.
/// Dropping the session itself is not rollback, and an accepted write is not
/// remote delivery, durable storage, or an application acknowledgement.
///
/// This is additive to `AsyncWriteExt::write_all`. No allocation, background
/// task or `Clone` bound is required. Like `write_all`, completion does NOT flush
/// or shut down the writer; those are separate operations owned by the caller.
///
/// Cooperative cancellation returns [`io::ErrorKind::Interrupted`]. Callers
/// with a retry loop on `Interrupted` must check [`Cx::is_cancel_requested`] to
/// distinguish cancellation from an endpoint-level interruption (such as POSIX
/// `EINTR`); retrying on a cancelled context will spin without making progress.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) -> std::io::Result<()> {
/// use asupersync::io::WriteAllSession;
/// let mut output = Vec::new();
/// let mut session = WriteAllSession::new(&mut output, b"request");
/// assert_eq!(session.run(cx).await?, 7);
/// assert!(session.pending_bytes().is_empty());
/// # Ok(())
/// # }
/// ```
#[must_use = "retain the session to preserve accepted-write progress"]
pub struct WriteAllSession<'a, W> {
    writer: W,
    buffer: &'a [u8],
    pos: usize,
    poison: Option<&'static str>,
}

impl<W> fmt::Debug for WriteAllSession<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteAllSession")
            .field("written", &self.pos)
            .field("length", &self.buffer.len())
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl<'a, W> WriteAllSession<'a, W> {
    /// Retain the writer and source; performs no I/O and allocates nothing.
    pub fn new(writer: W, buffer: &'a [u8]) -> Self {
        Self {
            writer,
            buffer,
            pos: 0,
            poison: None,
        }
    }

    /// Bytes accepted by successful writes across all runs, not remote acks.
    #[must_use]
    pub fn bytes_written(&self) -> usize {
        self.pos
    }

    /// The suffix not yet reported accepted by the writer.
    ///
    /// Provider panics and impossible counts poison the session because actual
    /// endpoint effects may be unknown. Extracting this slice cannot make an
    /// ambiguous endpoint safe to retry.
    #[must_use]
    pub fn pending_bytes(&self) -> &[u8] {
        &self.buffer[self.pos..]
    }

    /// Bytes not yet reported accepted by the writer.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.pos
    }

    /// Whether every byte was accepted without poisoning the provider.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.poison.is_none() && self.pos == self.buffer.len()
    }

    /// Whether unknown provider effects prohibit automatic continuation.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_some()
    }

    /// Recover the writer, complete source and accepted-prefix length.
    ///
    /// Continue with `buffer[written..]`, not the original full source. This
    /// neither flushes nor shuts down the writer and never undoes committed I/O.
    #[must_use]
    pub fn into_parts(self) -> (W, &'a [u8], usize) {
        (self.writer, self.buffer, self.pos)
    }
}

impl<W: AsyncWrite + Unpin> WriteAllSession<'_, W> {
    /// Write or resume the source, returning cumulative accepted-write bytes.
    ///
    /// Cooperative cancellation wakes even when the writer is parked and returns
    /// `Interrupted` without forgetting progress. Callers retrying on
    /// `ErrorKind::Interrupted` should check `cx.is_cancel_requested()` to
    /// distinguish cooperative cancellation from an endpoint-level `EINTR`:
    /// retrying on a cancelled context will spin without making progress.
    /// Drop the borrowing future to pause, then retry on this same session with
    /// a live context. I/O errors and `WriteZero` retain the accepted prefix;
    /// retry only when the endpoint's protocol permits it. Automatic retries are
    /// deliberately absent.
    ///
    /// Completed runs are idempotent even with a cancelled context. Every poll
    /// makes at most 32 writer calls. A provider panic propagates unchanged and
    /// poisons continuation; a write count larger than the offered suffix also
    /// poisons the session and returns `InvalidData` before advancing the offset.
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
                let offered = &self.buffer[self.pos..];
                self.poison = Some(POISONED);
                let result = Pin::new(&mut self.writer).poll_write(task_cx, offered);
                self.poison = None;
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(written)) => {
                        if written > offered.len() {
                            let reason = "exact I/O writer accepted more bytes than offered";
                            self.poison = Some(reason);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                reason,
                            )));
                        }
                        // No suspension or user code between acceptance and
                        // persisting its offset in the caller-retained owner.
                        self.pos += written;
                    }
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

#[cfg(test)]
#[path = "write_tests.rs"]
mod tests;
