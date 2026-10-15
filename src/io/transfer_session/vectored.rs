//! Resumable scatter/gather writes without concatenating the source buffers.

use super::{Cancellation, POISONED, POLL_BUDGET};
use crate::cx::Cx;
use crate::io::AsyncWrite;
use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::Poll;

// Bound both provider descriptor counts and scanning work, including empty
// source slices. Larger source lists are processed in successive windows.
const MAX_SLICES: usize = 16;

/// A vectored write whose slice cursor survives cancellation and future drop.
///
/// The session borrows an immutable list of [`IoSlice`]s, not a concatenated
/// payload. Each provider call receives at most 16 nonempty slices. Writers
/// without vectored support use [`AsyncWrite::poll_write_vectored`]'s scalar
/// fallback. Construction checks the total length. Source bytes are not copied
/// into a combined buffer, and descriptor windows are built on the stack.
///
/// Keep the session when dropping a borrowing [`Self::run`] future. Accepted
/// writes cannot be rolled back, and completion means only provider acceptance,
/// not remote acknowledgement or durability. Completion does not flush or shut
/// down the writer. Retry I/O errors only when the endpoint's protocol permits.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) -> std::io::Result<()> {
/// use asupersync::io::transfer_session::WriteAllVectoredSession;
/// use std::io::IoSlice;
/// let buffers = [IoSlice::new(b"header"), IoSlice::new(b"body")];
/// let mut output = Vec::new();
/// let mut session = WriteAllVectoredSession::new(&mut output, &buffers)?;
/// assert_eq!(session.run(cx).await?, 10);
/// # Ok(())
/// # }
/// ```
#[must_use = "retain the session to preserve vectored-write progress"]
pub struct WriteAllVectoredSession<'a, W> {
    writer: W,
    buffers: &'a [IoSlice<'a>],
    slice: usize,
    offset: usize,
    written: usize,
    total: usize,
    poison: Option<&'static str>,
}

impl<W> fmt::Debug for WriteAllVectoredSession<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteAllVectoredSession")
            .field("written", &self.written)
            .field("length", &self.total)
            .field("slice", &self.slice)
            .field("offset", &self.offset)
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl<'a, W> WriteAllVectoredSession<'a, W> {
    /// Retain the writer and buffers without allocation or I/O.
    ///
    /// Scans the lengths once and returns `InvalidInput` if their sum cannot be
    /// represented by `usize`. No source bytes are copied or modified.
    pub fn new(writer: W, buffers: &'a [IoSlice<'a>]) -> io::Result<Self> {
        let total = buffers.iter().try_fold(0_usize, |total, buffer| {
            total.checked_add(buffer.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "vectored write length overflow")
            })
        })?;
        Ok(Self {
            writer,
            buffers,
            slice: 0,
            offset: 0,
            written: 0,
            total,
            poison: None,
        })
    }

    /// Cumulative bytes accepted by successful provider writes.
    #[must_use]
    pub fn bytes_written(&self) -> usize {
        self.written
    }

    /// Bytes not yet reported accepted by the writer.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.total - self.written
    }

    /// Whether every byte was accepted without ambiguous provider effects.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.poison.is_none() && self.written == self.total
    }

    /// Whether a provider panic or invalid count prohibits automatic retry.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_some()
    }

    /// Recover the writer, remaining slice list, and offset into its first slice.
    ///
    /// Start with `remaining[0][offset..]`, then the remaining whole slices.
    /// An empty list has offset zero. Empty slices may remain after completion.
    /// Extraction neither flushes nor makes a poisoned endpoint safe to retry.
    #[must_use]
    pub fn into_parts(self) -> (W, &'a [IoSlice<'a>], usize) {
        (self.writer, &self.buffers[self.slice..], self.offset)
    }

    fn advance(&mut self, mut accepted: usize) {
        self.written += accepted;
        // A valid count spans at most the bounded window just offered. Updating
        // the cursor invokes no user code and occurs before any suspension.
        while accepted != 0 {
            let remaining = self.buffers[self.slice].len() - self.offset;
            if accepted < remaining {
                self.offset += accepted;
                break;
            }
            accepted -= remaining;
            self.slice += 1;
            self.offset = 0;
        }
    }
}

impl<W: AsyncWrite + Unpin> WriteAllVectoredSession<'_, W> {
    /// Write or resume all slices, returning cumulative accepted-write bytes.
    ///
    /// Cancellation is a wake source even while the writer is parked. It returns
    /// `Interrupted` without resetting the cursor; resume with a live context.
    /// Check `cx.is_cancel_requested()` before retrying `Interrupted` so a
    /// cancelled context cannot cause a busy retry loop. Endpoint errors are
    /// returned unchanged and are not retried automatically.
    ///
    /// Each poll builds at most 32 windows of 16 source descriptors and makes
    /// at most 32 provider calls. A provider panic propagates unchanged and
    /// poisons further runs; an impossible count returns sticky `InvalidData`. Complete
    /// runs are idempotent, including with a subsequently cancelled context.
    pub async fn run(&mut self, cx: &Cx) -> io::Result<usize> {
        let mut cancellation = Cancellation { cx, token: None };
        poll_fn(|task_cx| {
            if let Some(reason) = self.poison {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)));
            }
            if self.is_complete() {
                return Poll::Ready(Ok(self.written));
            }
            cancellation.register(task_cx);
            for _ in 0..POLL_BUDGET {
                if let Err(error) = cancellation.check() {
                    return Poll::Ready(Err(error));
                }
                let mut window: [IoSlice<'_>; MAX_SLICES] =
                    std::array::from_fn(|_| IoSlice::new(&[]));
                let end = self.slice + (self.buffers.len() - self.slice).min(MAX_SLICES);
                let mut count = 0;
                let mut offered = 0;
                for index in self.slice..end {
                    let offset = if index == self.slice { self.offset } else { 0 };
                    let bytes = &self.buffers[index][offset..];
                    if !bytes.is_empty() {
                        window[count] = IoSlice::new(bytes);
                        count += 1;
                        offered += bytes.len();
                    }
                }
                if count == 0 {
                    self.slice = end;
                    self.offset = 0;
                    continue;
                }
                self.poison = Some(POISONED);
                let result = Pin::new(&mut self.writer)
                    .poll_write_vectored(task_cx, &window[..count]);
                self.poison = None;
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(accepted)) => {
                        if accepted > offered {
                            let reason = "vectored writer accepted more bytes than offered";
                            self.poison = Some(reason);
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)));
                        }
                        self.advance(accepted);
                    }
                }
                if self.is_complete() {
                    return Poll::Ready(Ok(self.written));
                }
            }
            task_cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
#[path = "vectored_tests.rs"]
mod tests;
