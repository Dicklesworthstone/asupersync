//! Ownership and results of exact-length, verified stream ingestion.
//!
//! Sessions are created by `sparse_writer::ScopedSparseWriter::receive_exact`
//! or its explicitly pinned and suffix-restart variants. The concrete driver
//! lives with that writer; the session owns its source and pending operation
//! between waits.

use super::sparse_writer::SparseWriterError;
use crate::fs::scoped::ScopedFsError;
use crate::types::Outcome;
use std::future::{Future, poll_fn};
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

/// Explicit bounds for one receive operation, checked before source polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedReceiveOptions {
    /// Maximum declared object length accepted from the trusted manifest.
    pub max_bytes: u64,
    /// Maximum total payload write receipts, including a retained prefix on
    /// restart plus the ceiling-divided number of new suffix chunks.
    /// Zero permits only an empty object.
    pub max_chunks: u32,
    /// Payload buffer size, in `1..=1_048_576` bytes.
    pub chunk_size: usize,
}

/// Failure outside the writer's domain outcome.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScopedReceiveError {
    /// Read-stage failure, including premature EOF and context interruption.
    /// `StreamChunkReader` reports read-stage checkpoint refusal as Interrupted.
    #[error("scoped receive source: {0}")]
    Source(#[source] io::Error),
    /// The existing filesystem gateway refused or failed an operation.
    #[error("scoped receive gateway: {0}")]
    Gateway(#[from] ScopedFsError),
    /// The terminal result has already been consumed.
    #[error("scoped receive result already consumed")]
    Completed,
    /// A previous poll unwound; unknown source progress must not be replayed.
    #[error("scoped receive cannot resume after a poll panic")]
    Poisoned,
}

/// Source/gateway failures remain distinct from the actual writer outcome.
pub type ScopedReceiveResult<T> = Result<Outcome<T, SparseWriterError>, ScopedReceiveError>;
pub(super) type ReceiveWork<R> =
    Pin<Box<dyn Future<Output = ScopedReceiveResult<(R, PathBuf)>> + Send>>;

/// Caller-owned, resumable borrowing wait for an exact-length receive and commit.
///
/// Dropping [`Self::wait`] retains the source, partial chunk, pending write and
/// finalization in this object. Polling another wait resumes the same operation;
/// it does not reread a prefix or repeat a completed write. No background task is
/// created. Keep polling, or drop this owner to abandon the operation.
///
/// Dropping this owner inherits the source's cleanup boundary and requests
/// cancellation of any admitted filesystem job. That job retains the writer,
/// payload and admission permit through retirement. Region close drains those
/// admitted jobs; it does not poll or destroy a caller-owned receive session.
/// A started finalization may publish despite cancellation. Staging is never
/// implicitly removed; use the writer's explicit cleanup API after drain.
///
/// All writer clones share the admission slot held by this session. Do not wait
/// for a clone's operation while leaving this owner unpolled: finish or drop it
/// first. [`Self::accepted_bytes`] observes progress without that admission slot.
#[must_use = "receive sessions do nothing until their wait is polled"]
pub struct ScopedReceive<R> {
    pub(super) work: Option<ReceiveWork<R>>,
    pub(super) source: Option<R>,
    pub(super) accepted: Arc<AtomicU64>,
    pub(super) poisoned: bool,
}

impl<R> std::fmt::Debug for ScopedReceive<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedReceive")
            .field("accepted_bytes", &self.accepted_bytes())
            .field("finished", &self.work.is_none())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<R> ScopedReceive<R> {
    /// Bytes covered by successful, observed chunk-write receipts.
    ///
    /// A suffix restart starts at zero until preflight succeeds, then includes
    /// the revalidated prefix as well as newly observed successful writes.
    /// This is not a durability or completion receipt. An in-flight or failed
    /// write can have additional filesystem effects not represented here.
    #[must_use]
    pub fn accepted_bytes(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Recover the source once, only after successful verified publication.
    ///
    /// Exactly the declared body (or remaining suffix on restart) was consumed
    /// from `AsyncRead`; no EOF probe or following protocol byte was requested.
    /// The source may have
    /// its own read-ahead buffer, which remains owned by the returned source.
    /// On terminal failure the source is dropped, not returned with ambiguous
    /// body progress for reuse.
    pub fn take_source(&mut self) -> Option<R> {
        self.source.take()
    }

    /// Drive the retained operation and consume its terminal outcome once.
    /// Dropping this borrowing wait alone cancels nothing and loses no progress.
    pub async fn wait(&mut self) -> ScopedReceiveResult<PathBuf> {
        poll_fn(|task| self.poll_wait(task)).await
    }

    pub(super) fn poll_wait(&mut self, task: &mut Context<'_>) -> Poll<ScopedReceiveResult<PathBuf>> {
        if self.poisoned {
            return Poll::Ready(Err(ScopedReceiveError::Poisoned));
        }
        let Some(work) = self.work.as_mut() else {
            return Poll::Ready(Err(ScopedReceiveError::Completed));
        };
        // Leave a sticky refusal if any provider poll unwinds. Never repoll an
        // async state machine after unknown source or filesystem progress.
        self.poisoned = true;
        let result = work.as_mut().poll(task);
        self.poisoned = false;
        let Poll::Ready(result) = result else {
            return Poll::Pending;
        };
        let retired = self.work.take();
        let result = match result {
            Ok(Outcome::Ok((source, path))) => {
                self.source = Some(source);
                Ok(Outcome::Ok(path))
            }
            Ok(Outcome::Err(error)) => Ok(Outcome::Err(error)),
            Ok(Outcome::Cancelled(reason)) => Ok(Outcome::Cancelled(reason)),
            Ok(Outcome::Panicked(payload)) => Ok(Outcome::Panicked(payload)),
            Err(error) => Err(error),
        };
        // Commit terminal state before arbitrary capture destruction.
        drop(retired);
        Poll::Ready(result)
    }
}
