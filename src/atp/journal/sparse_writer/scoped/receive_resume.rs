//! Revalidate the recorded local prefix before negotiating a receive restart.

use super::{Manifest, ManifestChunkCommitment, ScopedReceive, ScopedReceiveOptions,
    ScopedSparseWriter, ScopedWriterResult, SparseWriter, SparseWriterError};
use crate::atp::journal::sparse_writer::VerificationState;
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::types::Outcome;
use crate::io::AsyncRead;
use std::io;
use std::sync::Arc;

impl ScopedSparseWriter {
    /// Restart exact-length ingestion from a revalidated local prefix.
    ///
    /// Retain this writer after a failed or abandoned receive, then use
    /// [`Self::checked_receive_offset`] to negotiate a replacement source that
    /// starts at `offset` in the same trusted object. This method does not seek,
    /// skip bytes, reconnect, or infer the peer's position. On first poll it
    /// rechecks the offset, declared size, receipt count and all retained chunk
    /// hashes under one admission slot, before polling the replacement source.
    /// A stale offset or changed/corrupt prefix refuses without consuming it.
    ///
    /// The original prefix is retained; only the remaining declared bytes are
    /// requested. `max_bytes` bounds the entire object and `max_chunks` bounds
    /// existing receipts plus the new suffix chunks, including across repeated
    /// retries with different chunk sizes. Whole-object verification always runs
    /// again before publication. A full prefix requests no source bytes but must
    /// still pass that verification. Success returns the source through the
    /// session, with subsequent protocol bytes untouched.
    ///
    /// This is in-process recovery of the original writer, not persisted journal
    /// recovery. Drop/finish the old session first. A terminal or unresolved
    /// publication cannot restart. Existing wait ownership, source-error and
    /// late-publication-after-cancellation rules still apply. Progress is zero
    /// until preflight succeeds, then includes the checked prefix.
    pub fn resume_exact_at<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
        offset: u64,
    ) -> io::Result<ScopedReceive<R>>
    where
        R: AsyncRead + Unpin + Send + 'static,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.receive_session(cx, source, manifest, options, None, Some(offset))
    }

    /// Resume a chunk-only file using an independently trusted manifest pin.
    ///
    /// The pin is checked before source reads and again at finalization, with no
    /// unpinned fallback. Local receipt hashes only validate retained storage;
    /// they never replace the sender's commitment to the complete object.
    /// All restart, framing and quota rules are those of [`Self::resume_exact_at`].
    pub fn resume_exact_at_with_chunk_commitment<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
        offset: u64,
        expected: ManifestChunkCommitment,
    ) -> io::Result<ScopedReceive<R>>
    where
        R: AsyncRead + Unpin + Send + 'static,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.receive_session(cx, source, manifest, options, Some(expected), Some(offset))
    }

    /// Re-read recorded chunks and return the contiguous local receive offset.
    ///
    /// Call after a failed receive has terminated or its owner has been dropped.
    /// The shared admission gate waits for any earlier disk operation to finish,
    /// so this observes actual successful write receipts, not a borrowing wait's
    /// possibly stale `accepted_bytes` counter. Every retained chunk is rehashed
    /// on the existing blocking pool before its bytes count toward the offset.
    ///
    /// This is an in-process observation, not a reservation, authenticated sender
    /// proof, or durable crash-recovery checkpoint. It requires this writer's
    /// original live ledger and declared size. A fresh writer without a size,
    /// noncontiguous receipts, corrupt/truncated storage, cancellation, or sealed
    /// publication refuses. Detected inconsistency invalidates old verification;
    /// it never changes bytes, truncates a file, or repairs the receipt ledger.
    ///
    /// Another clone can change the writer after this call returns. A resumed
    /// receive must revalidate the expected offset while holding admission.
    /// Work is proportional to the recorded prefix; a running filesystem call
    /// is not preempted by cancellation. Host pathname races remain out of scope.
    pub async fn checked_receive_offset<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<u64>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| match checked_prefix(writer) {
            Ok(offset) => Outcome::Ok(offset),
            Err(error) => Outcome::Err(error),
        })
        .await
    }
}

pub(super) fn checked_prefix(writer: &SparseWriter) -> Result<u64, SparseWriterError> {
    let _operation = writer.operation.lock();
    let mut state = writer.lock_state();
    SparseWriter::require_accepting(&state)?;
    let result = (|| {
        let invalid = |message: &str| SparseWriterError::VerificationFailed(message.to_owned());
        let length = state.expected_size
            .ok_or_else(|| invalid("receive checkpoint requires a declared size"))?;
        let mut offset = 0_u64;
        for (start, chunk) in &state.written_chunks {
            if *start != offset || chunk.offset != *start || chunk.size == 0 {
                return Err(invalid("receive checkpoint requires contiguous write receipts"));
            }
            offset = offset.checked_add(chunk.size)
                .filter(|end| *end <= length)
                .ok_or_else(|| invalid("receive checkpoint range exceeds the declared size"))?;
        }
        if state.range_tracker.total_bytes() != offset
            || !state.range_tracker.is_contiguous_to(offset)
        {
            return Err(invalid("receive checkpoint ranges disagree with write receipts"));
        }
        let Some(file) = state.temp_file.as_ref() else {
            if offset == 0 && state.temp_path.is_none() {
                return Ok(offset);
            }
            return Err(SparseWriterError::NoTempFile);
        };
        if state.temp_path.is_none() {
            return Err(SparseWriterError::NoTempFile);
        }
        let file_length = file.metadata()
            .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?.len();
        // Preallocation and an unreceipted partial write may extend past offset.
        // Those bytes do not count as received and must be supplied again.
        if file_length < offset || file_length > length {
            return Err(invalid("receive checkpoint storage length is inconsistent"));
        }
        let mut file = file.try_clone()
            .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?;
        for (start, chunk) in &state.written_chunks {
            if SparseWriter::hash_file_range(&mut file, *start, chunk.size)? != chunk.hash {
                return Err(invalid("receive checkpoint chunk hash mismatch"));
            }
        }
        Ok(offset)
    })();
    if let Err(error) = &result {
        state.verification_state = VerificationState::Failed { reason: error.to_string() };
    }
    result
}

#[cfg(test)]
#[path = "receive_resume_inline_tests.rs"]
mod tests;
