//! Exact scatter reads with retained progress and bounded descriptor windows.

use super::{Cancellation, POISONED, POLL_BUDGET};
use crate::cx::Cx;
use crate::io::AsyncReadVectored;
use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::task::Poll;

const MAX_SLICES: usize = 16;
const REPLACED_SLICES: &str =
    "vectored reader changed destination descriptors; endpoint effects are unknown";

/// An exact vectored read whose filled-prefix cursor survives future drop.
///
/// Retains an exclusive borrow of the caller's destination plan. Reads go
/// directly into these buffers without a combined staging allocation. The
/// source may implement native scatter reads or the trait's scalar fallback.
/// Keep the session across cancelled or dropped [`Self::run`] futures.
///
/// This is an in-process continuation, not rollback. The count records only
/// bytes reported by successful provider reads. A provider must not consume
/// unreported input on `Pending` or `Err`, nor replace the temporary descriptors
/// it receives. Unreported effects cannot be recovered by this session.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) -> std::io::Result<()> {
/// use asupersync::io::transfer_session::ReadExactVectoredSession;
/// use std::io::IoSliceMut;
/// let mut header = [0; 4];
/// let mut body = [0; 7];
/// let mut buffers = [IoSliceMut::new(&mut header), IoSliceMut::new(&mut body)];
/// let mut session = ReadExactVectoredSession::new(&b"HEADpayloadtail"[..], &mut buffers)?;
/// assert_eq!(session.run(cx).await?, 11);
/// let (source, _, read) = session.into_parts();
/// assert_eq!(read, 11);
/// assert_eq!(source, b"tail");
/// # Ok(())
/// # }
/// ```
#[must_use = "retain the session to preserve vectored-read progress"]
pub struct ReadExactVectoredSession<'a, 'buf, R> {
    reader: R,
    buffers: &'a mut [IoSliceMut<'buf>],
    slice: usize,
    offset: usize,
    read: usize,
    total: usize,
    poison: Option<&'static str>,
}

impl<R> fmt::Debug for ReadExactVectoredSession<'_, '_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadExactVectoredSession")
            .field("read", &self.read)
            .field("length", &self.total)
            .field("slice", &self.slice)
            .field("offset", &self.offset)
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl<'a, 'buf, R> ReadExactVectoredSession<'a, 'buf, R> {
    /// Retain the reader and destinations; performs no I/O or allocation.
    ///
    /// Scans lengths once and returns `InvalidInput` if their sum exceeds
    /// `usize::MAX`. Descriptors and buffer contents remain unchanged.
    pub fn new(reader: R, buffers: &'a mut [IoSliceMut<'buf>]) -> io::Result<Self> {
        let total = buffers.iter().try_fold(0_usize, |total, buffer| {
            total.checked_add(buffer.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "vectored read length overflow")
            })
        })?;
        Ok(Self {
            reader,
            buffers,
            slice: 0,
            offset: 0,
            read: 0,
            total,
            poison: None,
        })
    }

    /// Cumulative filled bytes reported by successful provider reads.
    #[must_use]
    pub fn bytes_read(&self) -> usize {
        self.read
    }

    /// Bytes still needed to fill the destination plan.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.total - self.read
    }

    /// Whether every destination was filled without ambiguous provider effects.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.poison.is_none() && self.read == self.total
    }

    /// Whether a provider panic, descriptor mutation or invalid count forbids retry.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_some()
    }

    /// Iterate the reported filled prefix in destination order, without copying.
    ///
    /// Yields one slice per destination, including empty slices for destinations
    /// not yet reached. Unreported effects after a provider failure are excluded.
    pub fn filled_slices(&self) -> impl Iterator<Item = &[u8]> {
        let mut remaining = self.read;
        self.buffers.iter().map(move |buffer| {
            let n = buffer.len().min(remaining);
            remaining -= n;
            &buffer[..n]
        })
    }

    /// Recover the reader, the COMPLETE destination plan and filled-prefix length.
    ///
    /// The first `read` bytes across the plan have already been consumed from the
    /// reader. Preserve those bytes and resume after them, not at the first
    /// destination. Recovery does not make a poisoned provider safe to retry.
    #[must_use]
    pub fn into_parts(self) -> (R, &'a mut [IoSliceMut<'buf>], usize) {
        (self.reader, self.buffers, self.read)
    }

    fn advance(&mut self, mut filled: usize) {
        self.read += filled;
        while filled != 0 {
            let remaining = self.buffers[self.slice].len() - self.offset;
            if filled < remaining {
                self.offset += filled;
                break;
            }
            filled -= remaining;
            self.slice += 1;
            self.offset = 0;
        }
    }
}

impl<R: AsyncReadVectored + Unpin> ReadExactVectoredSession<'_, '_, R> {
    /// Fill or resume the destination plan, returning cumulative filled bytes.
    ///
    /// Explicit cancellation wakes a parked reader and returns `Interrupted`.
    /// Check `cx.is_cancel_requested()` before retrying that error. EOF before
    /// completion returns `UnexpectedEof`; other errors are returned unchanged,
    /// without automatic retry. Completed calls are idempotent even after cancel.
    /// Each poll constructs at most 32 windows of 16 original descriptors.
    ///
    /// A provider panic propagates unchanged and poisons the session. Descriptor
    /// changes and counts beyond the offered window return sticky `InvalidData`
    /// before advancing progress. No session can undo unreported I/O effects.
    pub async fn run(&mut self, cx: &Cx) -> io::Result<usize> {
        let mut cancellation = Cancellation { cx, token: None };
        poll_fn(|task_cx| {
            if let Some(reason) = self.poison {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)));
            }
            if self.is_complete() {
                return Poll::Ready(Ok(self.read));
            }
            cancellation.register(task_cx);
            for _ in 0..POLL_BUDGET {
                if let Err(error) = cancellation.check() {
                    return Poll::Ready(Err(error));
                }
                let end = self.slice + (self.buffers.len() - self.slice).min(MAX_SLICES);
                // Reborrow disjoint buffers into TEMPORARY descriptors. Even a
                // misbehaving provider cannot replace the retained caller plan.
                let outcome = {
                    let mut window: [IoSliceMut<'_>; MAX_SLICES] =
                        std::array::from_fn(|_| IoSliceMut::new(&mut []));
                    let mut identities = [(std::ptr::null::<u8>(), 0_usize); MAX_SLICES];
                    let mut count = 0;
                    let mut offered = 0;
                    for (index, buffer) in self.buffers[self.slice..end].iter_mut().enumerate() {
                        let offset = if index == 0 { self.offset } else { 0 };
                        let bytes = &mut buffer[offset..];
                        if !bytes.is_empty() {
                            identities[count] = (bytes.as_ptr(), bytes.len());
                            offered += bytes.len();
                            window[count] = IoSliceMut::new(bytes);
                            count += 1;
                        }
                    }
                    if count == 0 {
                        None
                    } else {
                        self.poison = Some(POISONED);
                        let result = Pin::new(&mut self.reader)
                            .poll_read_vectored(task_cx, &mut window[..count]);
                        let intact = window[..count].iter().zip(&identities[..count]).all(
                            |(buffer, &(start, length))| {
                                std::ptr::eq(buffer.as_ptr(), start) && buffer.len() == length
                            },
                        );
                        Some((result, intact, offered))
                    }
                };
                let Some((result, intact, offered)) = outcome else {
                    self.slice = end;
                    self.offset = 0;
                    continue;
                };
                if !intact {
                    self.poison = Some(REPLACED_SLICES);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        REPLACED_SLICES,
                    )));
                }
                self.poison = None;
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    Poll::Ready(Ok(filled)) => {
                        if filled > offered {
                            let reason = "vectored reader reported more bytes than offered";
                            self.poison = Some(reason);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                reason,
                            )));
                        }
                        self.advance(filled);
                    }
                }
                if self.is_complete() {
                    return Poll::Ready(Ok(self.read));
                }
            }
            task_cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
#[path = "read_vectored_tests.rs"]
mod tests;
