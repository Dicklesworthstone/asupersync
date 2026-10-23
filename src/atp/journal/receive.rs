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
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
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
    /// Initial checkpoint preparation cannot be installed after body admission.
    /// The refused preparation call does not poll the source or stop the receive.
    #[error("scoped receive preparation is too late: body already admitted")]
    PreparationTooLate,
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

/// Exact-length reception with automatic durable checkpoints and journaled commit.
///
/// The existing journaled finalizer supplies the trusted manifest, optional pin,
/// sole journal owner, restoration limits and caller-selected timestamp. Receive
/// byte/receipt limits are additionally narrowed by those restoration limits.
/// The timestamp is reused; ordering uses journal sequences, not wall-clock time.
pub struct JournalReceiveRequest {
    /// Authority, journal ownership and limits used by every checkpoint and commit.
    pub commit: super::JournalCommitRequest,
    /// Source chunking and total receive limits, including a retained prefix.
    pub options: ScopedReceiveOptions,
    /// Nonzero newly written byte interval between checkpoints. Checkpoints occur
    /// at chunk boundaries, so the interval may be exceeded by less than a chunk.
    /// The initial prefix and final complete body are always checkpointed.
    pub checkpoint_bytes: u64,
    /// None requires a fresh writer; Some requires the same checked contiguous
    /// prefix as `resume_exact_at`. The source must already start at that offset.
    /// No seek, skip, reconnect, or offset negotiation is performed implicitly.
    pub resume_offset: Option<u64>,
}

/// Actual receive result and independently retained journal/publication evidence.
///
/// A failed read/write/checkpoint does not roll back earlier staging or records.
/// A successful outcome requires verified publication AND synchronized completion.
pub struct JournalReceiveReport {
    /// Original owner returned even after ordinary source or domain failure.
    /// None means a gateway failure lost the submitted owner, including admission
    /// refusal: reopen storage rather than guessing which records reached disk.
    pub journal: Option<super::AppendJournal>,
    /// None means finalization's gateway did not return its observation. It must
    /// never be interpreted as NotAttempted. A Confirmed publication survives a
    /// completion-record error, independently of the receive outcome below.
    pub publication: Option<super::JournalPublication>,
    /// Source/gateway failures and the canonical writer's Outcome remain distinct.
    pub outcome: ScopedReceiveResult<PathBuf>,
}

/// Result of preparing recovery evidence before any receive-body effect.
///
/// Preparation never reads the source or publishes even an empty object. A
/// failed preflight returns its actual report and journal owner, not an invented
/// successful checkpoint or a second way to recover a consumed terminal result.
pub enum JournalReceivePreparation {
    /// The initial local prefix and its journal records are synchronized. The
    /// receive remains paused until `ScopedJournalReceive::wait` is polled.
    Checkpoint(Arc<super::JournalCheckpoint>),
    /// Preparation terminated the receive. This report is consumed once, just
    /// like a report returned by `wait`; inspect its journal and actual outcome.
    Stopped(JournalReceiveReport),
}

// This is a session-local admission latch, not a concurrently polled primitive.
// Only the session changes Held back to Open, immediately before repolling work.
// No task or filesystem worker waits on this latch; a held receive simply stays
// in its owning future, retaining the existing writer admission permit. Only
// the driver can publish Prepared after observing successful job retirement;
// seeing a checkpoint snapshot while its producing job is still pending is
// insufficient for returning preparation success.
#[derive(Default)]
pub(super) struct ReceiveStartGate(AtomicU8);

impl ReceiveStartGate {
    const OPEN: u8 = 0;
    const HELD: u8 = 1;
    const ADMITTED: u8 = 2;
    const PREPARED: u8 = 3;

    fn hold(&self) -> bool {
        match self.0.compare_exchange(
            Self::OPEN, Self::HELD, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_) | Err(Self::HELD | Self::PREPARED) => true,
            Err(_) => false,
        }
    }

    fn release(&self) {
        // Never undo body admission after an earlier wait has started it.
        let _ = self.0.try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            matches!(state, Self::HELD | Self::PREPARED).then_some(Self::OPEN)
        });
    }

    fn is_prepared(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::PREPARED
    }

    pub(super) fn poll_admit(&self) -> Poll<()> {
        let previous = self.0.try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            match state {
                Self::OPEN => Some(Self::ADMITTED),
                Self::HELD => Some(Self::PREPARED),
                _ => None,
            }
        });
        match previous {
            Ok(Self::OPEN) | Err(Self::ADMITTED) => Poll::Ready(()),
            _ => Poll::Pending,
        }
    }
}

pub(super) type JournalCheckpointSlot =
    Arc<parking_lot::Mutex<Option<Arc<super::JournalCheckpoint>>>>;
pub(super) type JournalReceiveWork<R> = Pin<
    Box<dyn Future<Output = (Option<R>, JournalReceiveReport)> + Send>,
>;

/// Receive owner that retains journal work across dropped borrowing waits.
///
/// This uses the same source/chunk/write driver as ScopedReceive. One writer
/// admission slot spans initial checkpoint, source reads, periodic checkpoints,
/// and finalization. Each checkpoint finishes before the next source poll.
/// Running work keeps the journal and permit through region drain, including
/// when this session is dropped. Dropping the session is not rollback or cleanup.
///
/// Keep driving the session or drop it before awaiting another writer clone.
/// The snapshot accessor below never takes the writer/journal locks; its short
/// metadata lock is never held across disk work or destruction of old snapshots.
/// Persist the initial snapshot's source path in the application's trusted
/// recovery catalog: this type does not install a persistent path catalog. Use
/// `prepare_checkpoint` to get that evidence without allowing source reads or
/// publication; ordinary `wait` retains its existing automatic-start behavior.
#[must_use = "journaled receives need a polled wait or checkpoint preparation"]
pub struct ScopedJournalReceive<R> {
    pub(super) work: Option<JournalReceiveWork<R>>,
    pub(super) source: Option<R>,
    pub(super) accepted: Arc<AtomicU64>,
    pub(super) checkpoint: JournalCheckpointSlot,
    pub(super) start: Arc<ReceiveStartGate>,
    pub(super) poisoned: bool,
}

impl<R> std::fmt::Debug for ScopedJournalReceive<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedJournalReceive")
            .field("accepted_bytes", &self.accepted_bytes())
            .field("finished", &self.work.is_none())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<R> ScopedJournalReceive<R> {
    /// Actual successful writes observed by the receive driver, including bytes
    /// whose subsequent checkpoint failed. Not a durable or publication receipt.
    #[must_use]
    pub fn accepted_bytes(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Latest fully synchronized local checkpoint from this invocation.
    ///
    /// None includes preflight refusal and an unconfirmed first checkpoint.
    /// A retained snapshot remains historical: later writes, explicit cleanup
    /// or publication can change the source path. It never grants permission to
    /// resume after a commit intent. Always reopen/authenticate current history.
    /// This clones only an Arc, not the receipt table. Retaining many snapshots
    /// is a caller-controlled memory cost outside the payload-buffer limit.
    #[must_use]
    pub fn last_checkpoint(&self) -> Option<Arc<super::JournalCheckpoint>> {
        self.checkpoint.lock().clone()
    }

    /// Return the source once, only after verified, journal-confirmed publication.
    /// Following protocol bytes remain unread. Failure never returns a source
    /// with an ambiguous body cursor for accidental reuse.
    pub fn take_source(&mut self) -> Option<R> {
        self.source.take()
    }

    /// Prepare the initial checkpoint without reading any receive-body bytes.
    ///
    /// On Checkpoint, save its source path, expected manifest and protected key
    /// reference in the application's trusted durable recovery catalog before
    /// polling `wait`. The same admission slot keeps writer clones from changing
    /// staging during that catalog operation. Do not await a writer clone while
    /// the session is paused. This method does not write the catalog itself.
    ///
    /// Fresh, resumed, complete-prefix and empty objects all stop before source
    /// polling AND finalization. Preparing twice returns the same initial Arc.
    /// Dropping a borrowing preparation wait retains all admitted work and the
    /// pause; another preparation continues it, or `wait` explicitly opens it.
    /// Dropping the whole session preserves the existing drain/evidence rules.
    ///
    /// Stopped returns the terminal report and journal ownership exactly once.
    /// After body admission this refuses with PreparationTooLate without polling
    /// or disrupting that operation. This is not a later checkpoint scheduler.
    pub async fn prepare_checkpoint(
        &mut self,
    ) -> Result<JournalReceivePreparation, ScopedReceiveError> {
        if self.poisoned {
            return Err(ScopedReceiveError::Poisoned);
        }
        if self.work.is_none() {
            return Err(ScopedReceiveError::Completed);
        }
        if !self.start.hold() {
            return Err(ScopedReceiveError::PreparationTooLate);
        }
        poll_fn(|task| match self.poll_report(task) {
            Poll::Ready(Ok(report)) => {
                Poll::Ready(Ok(JournalReceivePreparation::Stopped(report)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending if self.start.is_prepared() => match self.last_checkpoint() {
                Some(checkpoint) => {
                    Poll::Ready(Ok(JournalReceivePreparation::Checkpoint(checkpoint)))
                }
                None => Poll::Pending,
            },
            Poll::Pending => Poll::Pending,
        }).await
    }

    /// Drive the same operation and consume its report once.
    /// Dropping this wait alone does not cancel its retained source or disk job.
    /// Polling this explicitly releases any initial preparation pause; a caller
    /// that needs a durable recovery catalog must finish saving it beforehand.
    /// Consumed/poisoned session errors are outside the report; ordinary transfer
    /// failures return a report so journal ownership and evidence are not lost.
    pub async fn wait(&mut self) -> Result<JournalReceiveReport, ScopedReceiveError> {
        self.start.release();
        poll_fn(|task| self.poll_report(task)).await
    }

    // Both public waits publish exactly the same terminal ownership before
    // capture destruction. Preparation must not add a second receive/result path.
    fn poll_report(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Result<JournalReceiveReport, ScopedReceiveError>> {
        if self.poisoned {
            return Poll::Ready(Err(ScopedReceiveError::Poisoned));
        }
        let Some(work) = self.work.as_mut() else {
            return Poll::Ready(Err(ScopedReceiveError::Completed));
        };
        self.poisoned = true;
        let result = work.as_mut().poll(task);
        self.poisoned = false;
        let Poll::Ready((source, report)) = result else {
            return Poll::Pending;
        };
        let retired = self.work.take();
        self.source = source;
        // Publish terminal ownership before dropping arbitrary captures.
        drop(retired);
        Poll::Ready(Ok(report))
    }
}

#[cfg(test)]
mod preparation_gate_tests {
    use super::*;

    #[test]
    fn preparation_needs_the_driver_boundary_not_just_a_published_snapshot() {
        let gate = ReceiveStartGate::default();
        assert!(gate.hold());
        assert!(!gate.is_prepared());
        assert!(gate.hold(), "a dropped borrowing preparation can be resumed");
        assert!(!gate.is_prepared(), "holding alone is not preflight retirement");
        assert!(gate.poll_admit().is_pending());
        assert!(gate.is_prepared());
        assert!(gate.hold());
        assert!(gate.poll_admit().is_pending());
        gate.release();
        assert!(!gate.is_prepared());
        assert!(gate.poll_admit().is_ready());
        assert!(!gate.hold(), "late preparation cannot close an admitted body");
        gate.release();
        assert!(gate.poll_admit().is_ready());
    }

    #[test]
    fn ordinary_wait_and_abandoned_preparation_need_no_external_wake() {
        let ordinary = ReceiveStartGate::default();
        ordinary.release();
        assert!(ordinary.poll_admit().is_ready());
        assert!(!ordinary.hold());

        let abandoned = ReceiveStartGate::default();
        assert!(abandoned.hold());
        // A regular wait may replace preparation before the preflight job ends.
        abandoned.release();
        assert!(abandoned.poll_admit().is_ready());
        assert!(!abandoned.is_prepared());
        assert!(!abandoned.hold());
    }
}
