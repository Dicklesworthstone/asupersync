//! Verification and publication as one admitted, region-owned operation.

use super::{Manifest, ManifestChunkCommitment, ScopedSparseWriter, ScopedWriterResult, SparseWriter, SparseWriterError};
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::types::Outcome;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

impl ScopedSparseWriter {
    /// Synchronize the current staging inode without verifying or publishing it.
    ///
    /// This is an explicit flush barrier, independent of the configured automatic
    /// fsync policy (including `Never`). It serializes with writes through the
    /// same FIFO admission and runs on the region-owned blocking pool. An empty
    /// staging inode is created when necessary. Only a successful `sync_all`
    /// marks the already-written chunks synced; later writes need another barrier.
    ///
    /// The writer remains accepting and its content-verification state is not
    /// promoted. This does not fill sparse holes, persist a journal checkpoint,
    /// synchronize the parent directory, or authorize final publication. A failed
    /// barrier leaves staging available for explicit retry. A started call drains
    /// after cancellation; successful late synchronization keeps its actual result.
    pub async fn sync_all<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.sync_staging_with(cx, File::sync_all).await
    }

    // The private barrier seam exercises real acquisition, serialization and
    // evidence updates. It cannot replace the writer or publication algorithm.
    async fn sync_staging_with<Caps, F>(&self, cx: &Cx<Caps>, sync: F) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&File) -> std::io::Result<()> + Send + 'static,
    {
        self.run(cx, move |writer| {
            let _operation = writer.operation.lock();
            let mut state = writer.lock_state();
            if let Err(error) = SparseWriter::require_accepting(&state) {
                return Outcome::Err(error);
            }
            if let Err(error) = writer.ensure_temp_file_open_locked(&mut state) {
                return Outcome::Err(error);
            }
            let Some(file) = state.temp_file.as_mut() else {
                return Outcome::Err(SparseWriterError::NoTempFile);
            };
            if let Err(error) = file.flush().and_then(|()| sync(file)) {
                return Outcome::Err(SparseWriterError::SyncFailed(error.to_string()));
            }
            for chunk in state.written_chunks.values_mut() {
                chunk.synced = true;
            }
            Outcome::Ok(())
        }).await
    }

    /// Verify the supplied trusted manifest and publish without a clone interleaving.
    ///
    /// Unlike separate `verify(...).await` and `commit(...).await` calls, this
    /// holds one FIFO admission slot and one blocking job across both stages.
    /// Every call performs fresh verification; it never relies on another
    /// caller's previously installed verification. Failed verification leaves
    /// staging available and does not start publication or its durability barrier.
    ///
    /// Once the job starts, cancellation requests drain, not rollback: successful
    /// verification may still be followed by publication after a cancellation
    /// request or dropped wait. The exact terminal outcome is preserved. Use
    /// separate methods when an application needs a decision point between
    /// verification and commit, and coordinate ownership of clones at that point.
    ///
    /// A successful finalization seals the writer. Calling this method again
    /// refuses rather than pretending to reverify a consumed staging inode; use
    /// [`Self::commit`] to retrieve the already committed path. A failed commit
    /// remains sealed with its existing uncertainty semantics. No protection
    /// against external filesystem mutation or pathname races is added, and
    /// `CopyAndVerify` retains its non-atomic visibility semantics.
    pub async fn verify_and_commit<Caps>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
    ) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.verify_publish_with(cx, manifest, None, |writer| {
            writer.commit_with_fsync(File::sync_all)
        }).await
    }

    /// Verify an independently trusted chunk commitment and publish in one job.
    ///
    /// The expected commitment must come from the trusted producer, not be
    /// computed from received untrusted metadata. This uses the same canonical
    /// identity, coverage, chunk and whole-file checks as pinned verification.
    /// A wrong pin cannot reach publication, even after an earlier successful
    /// verification. Admission, cancellation and retry semantics are those of
    /// [`Self::verify_and_commit`]; no legacy-root fallback is introduced.
    pub async fn verify_and_commit_with_chunk_commitment<Caps>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
        expected: ManifestChunkCommitment,
    ) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.verify_publish_with(cx, manifest, Some(expected), |writer| {
            writer.commit_with_fsync(File::sync_all)
        }).await
    }

    // One driver holds `run`'s owned permit across the real verifier and the
    // real publisher. The private continuation permits state-witnessed tests
    // between them and sync-failure injection through the canonical commit.
    // No public caller can replace verification or the publication operation.
    async fn verify_publish_with<Caps, F>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
        expected: Option<ManifestChunkCommitment>,
        publish: F,
    ) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> Outcome<PathBuf, SparseWriterError> + Send + 'static,
    {
        self.run(cx, move |writer| {
            match writer.verify_inner(&manifest, expected.as_ref()) {
                Outcome::Ok(()) => publish(writer),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            }
        }).await
    }
}

#[cfg(test)]
#[path = "finalize_inline_tests.rs"]
mod tests;
