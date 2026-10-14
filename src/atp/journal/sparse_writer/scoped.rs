//! Sparse-file operations on the existing region-owned filesystem gateway.
//!
//! This is an execution adapter over `SparseWriter`, not another verifier,
//! journal, or publication state machine. Every operation uses `ScopedFs` and
//! therefore the runtime's drained blocking tasks. No call is polled on a pool
//! thread by a nested executor, and no inline or detached fallback is used.
//!
//! Each call is owned by its explicit context's region. Dropping the wait asks
//! the child to cancel; region close still waits for a running OS operation and
//! the destruction of abandoned results/captures. A started operation is not
//! preempted or rolled back. Its real `Outcome` survives caller cancellation.
//! Cancellation of a call does not implicitly discard the transfer's staging
//! file: request `cancel` with an authorized, non-cancelled cleanup context.
//!
//! The adapter currently adopts a writer created through the historical
//! constructor. That constructor's capability probes are still a synchronous
//! host boundary. The operations after adoption, including preallocation and
//! observation of locked state, are dispatched to the owned blocking pool.
//! Existing path-race and publication-policy limitations remain unchanged.

use super::{
    ChunkRange, Manifest, ManifestChunkCommitment, SparseWriter, SparseWriterError,
    SparseWriterStats, WriteOptions,
};
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::fs::scoped::ScopedFsError;
use crate::types::Outcome;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

/// Runtime admission/retirement and the writer's actual outcome are separate.
///
/// `Err` reports a `ScopedFs` authority, checkpoint, admission, or child failure.
/// `Ok(outcome)` preserves exactly what the running writer returned, including
/// a filesystem/verification error or a successful effect after cancellation.
/// Neither an outer nor an inner error is evidence that publication rolled back.
pub type ScopedWriterResult<T> = Result<Outcome<T, SparseWriterError>, ScopedFsError>;

/// A shared sparse writer whose operations execute as region-owned pool jobs.
///
/// Clones refer to one writer and one serialized lifecycle. There is no raw
/// writer accessor and no borrowed file/data pointer crosses the pool boundary.
/// The adapter itself does not own a region: each operation requires an explicit
/// `Cx` with both I/O and spawn authority. A job retains the writer even after
/// all application handles and the borrowing wait have been dropped.
#[derive(Clone)]
pub struct ScopedSparseWriter {
    writer: Arc<SparseWriter>,
}

impl std::fmt::Debug for ScopedSparseWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not take the writer state lock on the caller's async thread.
        f.debug_struct("ScopedSparseWriter").finish_non_exhaustive()
    }
}

impl SparseWriter {
    /// Move this prepared writer behind the region-owned pool execution API.
    ///
    /// Adoption performs no filesystem work and does not change verification,
    /// written ranges, staging descriptors, or terminal state. The historical
    /// constructor's probes are not retroactively made region-owned.
    #[must_use]
    pub fn into_scoped(self) -> ScopedSparseWriter {
        ScopedSparseWriter { writer: Arc::new(self) }
    }
}

impl ScopedSparseWriter {
    // `ScopedFs` is the single authority/checkpoint/admission/cancel/drain
    // implementation. Wrapping the domain outcome in Ok deliberately does not
    // convert successful late effects into an artificial cancellation result.
    async fn run<Caps, F, T>(&self, cx: &Cx<Caps>, operation: F) -> ScopedWriterResult<T>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> Outcome<T, SparseWriterError> + Send + 'static,
        T: Send + 'static,
    {
        let writer = Arc::clone(&self.writer);
        cx.scoped_fs().run_io(move |_| Ok(operation(&writer))).await
    }

    /// Set the expected file length; any preallocation runs on the pool.
    pub async fn set_expected_size<Caps>(&self, cx: &Cx<Caps>, size: u64) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| match writer.set_expected_size(size) {
            Ok(()) => Outcome::Ok(()),
            Err(error) => Outcome::Err(error),
        }).await
    }

    /// Write one owned chunk with the canonical range, hash, and fsync checks.
    ///
    /// Ownership of `data` moves into the job without a second payload copy.
    /// Dropping this wait need not undo a started write. Query actual ranges or
    /// statistics after its owning region drains instead of blindly resending.
    /// The caller chooses the allocation size; this method adds no size limit.
    pub async fn write_chunk<Caps>(
        &self,
        cx: &Cx<Caps>,
        offset: u64,
        data: Vec<u8>,
        options: WriteOptions,
    ) -> ScopedWriterResult<ChunkRange>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| writer.write_chunk_blocking(offset, &data, options)).await
    }

    /// Verify against a trusted immutable manifest without blocking a scheduler.
    ///
    /// The manifest `Arc` avoids copying its object/chunk tables for each call.
    /// Legacy root-only chunk authentication remains refused by the core.
    pub async fn verify<Caps>(&self, cx: &Cx<Caps>, manifest: Arc<Manifest>) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| writer.verify_inner(&manifest, None)).await
    }

    /// Verify every byte using an independently trusted chunk commitment.
    /// The same pinned verifier, identity checks and coverage checks are used.
    pub async fn verify_with_chunk_commitment<Caps>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
        expected: ManifestChunkCommitment,
    ) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| writer.verify_inner(&manifest, Some(&expected))).await
    }

    /// Publish using the existing sealed lifecycle and final durability barriers.
    ///
    /// A started commit drains even if the caller is cancelled. Its exact result
    /// is preserved. An error may follow visibility; it never implies rollback.
    pub async fn commit<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| writer.commit_with_fsync(File::sync_all)).await
    }

    /// Explicitly quarantine/clean up and permanently cancel an uncommitted writer.
    ///
    /// This is filesystem work, not a task-cancellation signal. Use a live,
    /// authorized cleanup context; an already-cancelled context refuses dispatch.
    /// A failed cleanup retains its evidence for retry. An unresolved publication
    /// cannot be discarded by this operation.
    pub async fn cancel<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, SparseWriter::cancel_blocking).await
    }

    /// Observe progress on the pool, not by contending on an async worker.
    pub async fn get_stats<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<SparseWriterStats>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| Outcome::Ok(writer.get_stats())).await
    }

    /// Observe whether all expected ranges are present without an async-thread lock.
    pub async fn is_complete<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<bool>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| Outcome::Ok(writer.is_complete())).await
    }
}

#[cfg(test)]
mod tests;
