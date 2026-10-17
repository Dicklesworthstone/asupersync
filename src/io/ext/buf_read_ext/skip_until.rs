//! Allocation-free, resumable delimiter discard with a retained byte allowance.

use crate::io::AsyncBufRead;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const POLL_BUDGET: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Reading,
    Delimiter,
    Eof,
    LimitExceeded,
    Poisoned,
}

/// Discards through one delimiter without allocating a record buffer.
///
/// The session borrows one reader and retains the cumulative consumed count.
/// Keep it across dropped [`Self::run`] waits and ordinary I/O errors: a new
/// wait continues the same record with the SAME remaining allowance. The bound
/// includes the delimiter and applies only to bytes consumed by this session,
/// not any prefix already accepted before the session was constructed.
///
/// Reaching EOF is success, but only [`Self::delimiter_found`] confirms a
/// delimiter boundary. A nonempty continuation beyond the allowance is
/// `InvalidData`, and remains unread. That refusal is sticky; increasing the
/// allowance requires deliberately recovering the reader and making a new
/// session. Recovery is not automatic, and consumed bytes cannot be restored.
///
/// A provider panic propagates and poisons the session before control returns
/// to the caller. Further runs refuse to replay unknown provider effects.
/// Dropping a borrowing wait is not a provider panic and does not poison it.
/// This is in-process continuation, not a producer-task join or crash recovery.
#[derive(Debug)]
#[must_use = "run the session or recover its reader explicitly"]
pub struct SkipUntilSession<'a, R: ?Sized> {
    reader: &'a mut R,
    delimiter: u8,
    max_bytes: usize,
    skipped: usize,
    state: State,
}

impl<'a, R: ?Sized> SkipUntilSession<'a, R> {
    /// Borrow a reader for a discard of at most `max_bytes`, including delimiter.
    /// Construction neither polls nor consumes input. Zero permits only EOF.
    pub fn new(reader: &'a mut R, delimiter: u8, max_bytes: usize) -> Self {
        Self {
            reader,
            delimiter,
            max_bytes,
            skipped: 0,
            state: State::Reading,
        }
    }

    /// Total bytes confirmed consumed by successful provider `consume` calls.
    /// This is a lower bound after a provider panic: its effects may be unknown.
    #[must_use]
    pub const fn bytes_skipped(&self) -> usize {
        self.skipped
    }

    /// Byte allowance remaining across every run, never reset by a dropped wait.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.max_bytes - self.skipped
    }

    /// Whether this session consumed its delimiter (rather than stopping at EOF).
    #[must_use]
    pub const fn delimiter_found(&self) -> bool {
        matches!(self.state, State::Delimiter)
    }

    /// Whether the provider returned an empty buffered slice before a delimiter.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        matches!(self.state, State::Eof)
    }

    /// Whether input beyond the allowance was observed and left unconsumed.
    #[must_use]
    pub const fn limit_exceeded(&self) -> bool {
        matches!(self.state, State::LimitExceeded)
    }

    /// Whether a provider panicked while its effects were still unclassified.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        matches!(self.state, State::Poisoned)
    }

    /// Recover the same reader at its current position without additional I/O.
    ///
    /// After a size refusal it is still inside the oversized record, not at a
    /// new frame. After a panic its exact source position may be unknown.
    #[must_use]
    pub fn into_inner(self) -> &'a mut R {
        self.reader
    }
}

impl<R: AsyncBufRead + Unpin + ?Sized> SkipUntilSession<'_, R> {
    /// Resume discarding and return the cumulative count across all runs.
    ///
    /// A successful delimiter or EOF is memoized: another run returns the same
    /// count without polling the reader. An ordinary provider error is returned
    /// unchanged, retaining progress for a protocol-authorized retry. Size
    /// refusals and provider panics never silently readmit input.
    ///
    /// This does not take a `Cx`, subscribe to cancellation, impose a deadline,
    /// or retire the source. A caller may cancel by dropping THIS borrowing wait
    /// while retaining the session. At most 32 provider refills occur per poll;
    /// reaching that work budget self-wakes and yields. There is no private
    /// byte buffer, but upstream buffering and provider responsiveness remain
    /// outside this operation's bounds.
    pub async fn run(&mut self) -> io::Result<usize> {
        poll_fn(|cx| self.poll_skip(cx)).await
    }

    fn poll_skip(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.is_poisoned() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "delimiter discard has unknown provider effects",
            )));
        }
        if self.limit_exceeded() {
            return Poll::Ready(Err(limit_error()));
        }
        if self.delimiter_found() || self.is_eof() {
            return Poll::Ready(Ok(self.skipped));
        }
        for _ in 0..POLL_BUDGET {
            let remaining = self.remaining();
            // User code may unwind after mutating its source. Keep the guard
            // armed across both the peek and its corresponding consumption.
            self.state = State::Poisoned;
            let (used, next) = {
                let available = match Pin::new(&mut *self.reader).poll_fill_buf(cx) {
                    Poll::Pending => {
                        self.state = State::Reading;
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => {
                        self.state = State::Reading;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(available)) => available,
                };
                let offered = available.len().min(remaining);
                match memchr::memchr(self.delimiter, &available[..offered]) {
                    Some(index) => (index + 1, State::Delimiter),
                    None if available.is_empty() => (0, State::Eof),
                    None if offered < available.len() => (offered, State::LimitExceeded),
                    None => (offered, State::Reading),
                }
            };
            if used != 0 {
                Pin::new(&mut *self.reader).consume(used);
            }
            // used <= max_bytes - skipped, including usize::MAX. Never
            // consume before proving that the cumulative count is representable.
            self.skipped += used;
            self.state = next;
            if self.limit_exceeded() {
                return Poll::Ready(Err(limit_error()));
            }
            if self.delimiter_found() || self.is_eof() {
                return Poll::Ready(Ok(self.skipped));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "delimiter discard exceeds max_bytes")
}

#[cfg(test)]
mod tests;
