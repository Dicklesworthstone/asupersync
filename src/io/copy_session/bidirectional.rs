//! Two-direction continuation over the same retained transfer engine.

use super::{Cancellation, CopySessionProgress, DEFAULT_CAPACITY, Direction, POLL_BUDGET, Step, buffer};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite};
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::task::Poll;

/// Independent cumulative progress in the two forwarding directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BidirectionalCopyProgress {
    /// Reads from endpoint A, writes/flushes/write-shutdowns to endpoint B.
    pub a_to_b: CopySessionProgress,
    /// Reads from endpoint B, writes/flushes/write-shutdowns to endpoint A.
    pub b_to_a: CopySessionProgress,
}

/// Caller-owned, resumable duplex forwarding, including independent half-closes.
///
/// Each direction owns one bounded buffer. Dropping `run` or returning an error
/// retains BOTH read-ahead suffixes and every completed write, flush and
/// shutdown. One blocked direction does not prevent the other from progressing.
/// EOF in A flushes and shuts down B's write side, while B-to-A continues.
/// The providers must support reading after write-side shutdown for that use.
///
/// This is in-process continuation, not reconnect/resume against a new peer.
/// Retain this owner across cancelled waits; dropping the owner itself can lose
/// read-ahead. No task is spawned and no I/O is attempted from Drop. Counters
/// measure accepted writes, not remote acknowledgement or durable publication.
#[must_use = "retain both endpoints and buffers until forwarding or explicit recovery completes"]
pub struct BidirectionalCopySession<A, B> {
    a: A,
    b: B,
    a_to_b: Direction,
    b_to_a: Direction,
}

impl<A, B> fmt::Debug for BidirectionalCopySession<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BidirectionalCopySession")
            .field("progress", &self.progress())
            .field("a_to_b_capacity", &self.a_to_b.buffer.len())
            .field("b_to_a_capacity", &self.b_to_a.buffer.len())
            .field("poisoned", &(self.a_to_b.poison.is_some() || self.b_to_a.poison.is_some()))
            .finish_non_exhaustive()
    }
}

impl<A, B> BidirectionalCopySession<A, B> {
    /// Retain the duplex endpoints and two 8 KiB buffers, without performing I/O.
    #[must_use]
    pub fn new(a: A, b: B) -> Self {
        Self { a, b,
            a_to_b: Direction::new(vec![0; DEFAULT_CAPACITY]),
            b_to_a: Direction::new(vec![0; DEFAULT_CAPACITY]) }
    }

    /// Use explicit positive buffer bounds for A-to-B and B-to-A, respectively.
    /// Zero capacity or an allocation failure is refused before any I/O.
    pub fn with_capacities(a: A, b: B, a_to_b: usize, b_to_a: usize) -> io::Result<Self> {
        if a_to_b == 0 || b_to_a == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "copy buffer capacities must be nonzero"));
        }
        Ok(Self { a, b,
            a_to_b: Direction::new(buffer(a_to_b)?),
            b_to_a: Direction::new(buffer(b_to_a)?) })
    }

    /// Observe both directions without polling or consuming bytes.
    #[must_use]
    pub fn progress(&self) -> BidirectionalCopyProgress {
        BidirectionalCopyProgress { a_to_b: self.a_to_b.progress(), b_to_a: self.b_to_a.progress() }
    }

    /// Both directions reached EOF, flushed and completed write-side shutdown.
    #[must_use]
    pub fn is_complete(&self) -> bool { self.a_to_b.complete(true) && self.b_to_a.complete(true) }

    /// Bytes already read from A that have not yet been accepted by B.
    #[must_use]
    pub fn pending_a_to_b(&self) -> &[u8] { &self.a_to_b.buffer[self.a_to_b.pos..self.a_to_b.len] }

    /// Bytes already read from B that have not yet been accepted by A.
    #[must_use]
    pub fn pending_b_to_a(&self) -> &[u8] { &self.b_to_a.buffer[self.b_to_a.pos..self.b_to_a.len] }

    /// Recover `(a, b, pending_a_to_b, pending_b_to_a)` without discarding bytes.
    /// Write each pending suffix to its destination BEFORE reading its source.
    /// Already completed write shutdowns are not reversed. After a provider panic
    /// or invalid progress report, external effects remain unknown and retry is
    /// not justified merely because these values can be recovered.
    #[must_use]
    pub fn into_parts(self) -> (A, B, Vec<u8>, Vec<u8>) {
        (self.a, self.b, self.a_to_b.into_pending(), self.b_to_a.into_pending())
    }
}

impl<A, B> BidirectionalCopySession<A, B>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    /// Resume forwarding until BOTH half-closes complete, or return the original I/O error.
    ///
    /// Returns cumulative `(a_to_b, b_to_a)` accepted-write byte counts. A
    /// cancelled context returns Interrupted with buffers and half-close progress
    /// intact. Retry with a live context only when both endpoint protocols permit
    /// it. There is no implicit retry, busy polling, detached work or drop-time I/O.
    /// Completed runs return the same counters without calling either endpoint.
    /// A provider panic poisons the WHOLE pair: both directions share endpoints.
    pub async fn run(&mut self, cx: &Cx) -> io::Result<(u64, u64)> {
        let mut cancellation = Cancellation { cx, token: None };
        poll_fn(|task_cx| {
            if self.is_complete() {
                return Poll::Ready(Ok((self.a_to_b.written, self.b_to_a.written)));
            }
            // Check both poisons before polling EITHER side. A prior B-to-A
            // provider panic may have invalidated A-to-B's shared endpoint too.
            if let Some(reason) = self.a_to_b.poison.or(self.b_to_a.poison) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)));
            }
            cancellation.register(task_cx);
            for _ in 0..(POLL_BUDGET / 2) {
                if let Err(error) = cancellation.check() { return Poll::Ready(Err(error)); }
                let a = match self.a_to_b.step(&mut self.a, &mut self.b, task_cx, true) {
                    Ok(step) => step,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                if let Err(error) = cancellation.check() { return Poll::Ready(Err(error)); }
                let b = match self.b_to_a.step(&mut self.b, &mut self.a, task_cx, true) {
                    Ok(step) => step,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                match (a, b) {
                    (Step::Done, Step::Done) => {
                        return Poll::Ready(Ok((self.a_to_b.written, self.b_to_a.written)));
                    }
                    (Step::Progress, _) | (_, Step::Progress) => {}
                    _ => return Poll::Pending,
                }
            }
            task_cx.waker().wake_by_ref();
            Poll::Pending
        }).await
    }
}

#[cfg(test)]
#[path = "bidirectional_tests.rs"]
mod tests;
