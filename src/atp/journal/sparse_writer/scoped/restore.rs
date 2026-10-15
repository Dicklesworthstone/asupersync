//! Rebuild private staging from authenticated journal evidence and actual bytes.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::atp::journal::{
    AppendJournal, JournalRecord, JournalRestoreLimits, JournalRestoreRequest, TransferResumeChunk,
};
use std::io::{Read, Seek, SeekFrom};
use sha2::{Digest, Sha256};

struct RestorePlan {
    object_id: ObjectId,
    total_size: u64,
    chunks: Vec<TransferResumeChunk>,
}

impl ScopedSparseWriter {
    /// Reopen journal and payload paths inside the same owned restore job.
    ///
    /// Unlike `restore_from_journal`, this entry point requires no synchronous
    /// journal reconstruction or source-file opening on the caller. All paths
    /// and the authentication key are explicitly supplied by the application.
    /// The journal directory must already exist; an absent directory is not
    /// initialized as an empty recovery history. Journal authentication, transfer
    /// status, identity and limits are checked before the payload path is opened.
    ///
    /// Uses the identical receipt checker and new-staging reconstruction as
    /// `restore_from_journal`. The returned writer remains unverified; restoring
    /// does not append subsequent write receipts or delete old journal/payload
    /// evidence. Path opens follow normal host semantics in a trusted directory,
    /// not a sandbox. Blocking journal parsing or an OS open cannot be preempted;
    /// checkpoints separate those stages and region close drains the whole job.
    pub async fn restore_from_storage<Caps>(
        cx: &Cx<Caps>,
        request: JournalRestoreRequest,
    ) -> ScopedWriterResult<Self>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        cx.scoped_fs().run_io(move |child| {
            let checkpoint = || child.checkpoint()
                .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error));
            checkpoint()?;
            if request.limits.max_chunk_bytes == 0 {
                return Ok(Outcome::Err(invalid("journal restore needs a nonzero payload-buffer limit")));
            }
            match std::fs::metadata(&request.journal_config.base_dir) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => return Ok(Outcome::Err(SparseWriterError::FileOpen(
                    "restore journal path is not a directory".to_owned(),
                ))),
                Err(error) => return Ok(Outcome::Err(SparseWriterError::FileOpen(
                    format!("restore journal directory: {error}"),
                ))),
            }
            checkpoint()?;
            let journal = match AppendJournal::new(request.journal_config, request.auth_key) {
                Outcome::Ok(journal) => journal,
                Outcome::Err(error) => return Ok(Outcome::Err(invalid(format!("journal restore: {error}")))),
                Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
                Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
            };
            checkpoint()?;
            let plan = match restore_plan(&journal, &request.transfer_id, request.limits) {
                Outcome::Ok(plan) => plan,
                Outcome::Err(error) => return Ok(Outcome::Err(error)),
                Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
                Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
            };
            checkpoint()?;
            let source = match File::open(&request.source_path) {
                Ok(source) => source,
                Err(error) => return Ok(Outcome::Err(SparseWriterError::FileOpen(
                    format!("restore source open: {error}"),
                ))),
            };
            restore_file(source, request.final_path, request.writer_config, plan, checkpoint)
                .map(|outcome| outcome.map(SparseWriter::into_scoped))
        }).await
    }

    /// Restore recorded ranges from an explicitly supplied whole-object file.
    ///
    /// The journal must have been reopened with its trusted authentication key.
    /// Only a resumable transfer with a consistent offer is accepted. Every
    /// recorded verified/written range is read at its logical object offset,
    /// hashed against the authenticated receipt, then copied into NEW private
    /// staging through the canonical writer. Journal `file_path` strings are
    /// never opened: the caller chooses the source descriptor explicitly.
    ///
    /// No source bytes are modified, removed, renamed or adopted for cleanup.
    /// No destination is published. Missing ranges remain missing, verification
    /// remains Pending, and the returned writer uses the existing write, pinned
    /// verification and finalization APIs. A contiguous prefix can continue with
    /// `checked_receive_offset` and `resume_exact_at`; sparse ranges can be filled
    /// with ordinary out-of-order writes. A complete restore still needs fresh
    /// whole-object verification before commit.
    ///
    /// Limits bound the declared object, restored receipts and payload scratch,
    /// not memory already used by the journal/index or its summary construction.
    /// One reusable buffer is sized to the largest admitted receipt. This costs
    /// local reads and a second staging copy, but does not redownload the prefix.
    /// It supports whole-object files, not individually packed chunk files.
    ///
    /// All work, including journal checks, source reads, construction, writes,
    /// and failure cleanup, runs in one region-owned blocking job. Checkpoints
    /// run between bounded reads and receipt writes. A syscall cannot be
    /// preempted; successful completion retains its actual result after late
    /// cancellation. Failed restores use the existing cancellation/quarantine
    /// policy for their new staging only. Cleanup on panic is best effort.
    /// Successfully returned writers have the normal explicit commit/cancel
    /// lifecycle, including when a successful result is abandoned by its caller.
    ///
    /// The journal authenticates receipts, not a network peer or log completeness.
    /// Final manifest authority and verification are still required. Concurrent
    /// external mutation, source sharing through cloned descriptors, and hostile
    /// parent-path replacement are outside this method's guarantees.
    pub async fn restore_from_journal<Caps>(
        cx: &Cx<Caps>,
        journal: Arc<AppendJournal>,
        transfer_id: String,
        source: File,
        final_path: PathBuf,
        config: SparseWriterConfig,
        limits: JournalRestoreLimits,
    ) -> ScopedWriterResult<Self>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        cx.scoped_fs().run_io(move |child| {
            let plan = match restore_plan(&journal, &transfer_id, limits) {
                Outcome::Ok(plan) => plan,
                Outcome::Err(error) => return Ok(Outcome::Err(error)),
                Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
                Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
            };
            let checkpoint = || child.checkpoint()
                .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error));
            restore_file(source, final_path, config, plan, checkpoint)
                .map(|outcome| outcome.map(SparseWriter::into_scoped))
        }).await
    }
}

fn invalid(message: impl Into<String>) -> SparseWriterError {
    SparseWriterError::VerificationFailed(message.into())
}

fn restore_plan(
    journal: &AppendJournal,
    transfer_id: &str,
    limits: JournalRestoreLimits,
) -> Outcome<RestorePlan, SparseWriterError> {
    if limits.max_chunk_bytes == 0 {
        return Outcome::Err(invalid("journal restore needs a nonzero payload-buffer limit"));
    }
    let summary = match journal.get_resume_summary(transfer_id) {
        Outcome::Ok(summary) => summary,
        Outcome::Err(error) => return Outcome::Err(invalid(format!("journal restore: {error}"))),
        Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => return Outcome::Panicked(payload),
    };
    if !summary.is_resumable() {
        return Outcome::Err(invalid("journal restore requires a resumable transfer"));
    }
    let Some(total_size) = summary.total_size else {
        return Outcome::Err(invalid("journal restore requires an offered object length"));
    };
    if total_size > limits.max_bytes
        || u64::try_from(summary.durable_chunks.len())
            .map_or(true, |count| count > u64::from(limits.max_chunks))
        || summary.durable_chunks.iter().any(|chunk| {
            usize::try_from(chunk.chunk_size)
                .map_or(true, |size| size > limits.max_chunk_bytes)
        })
    {
        return Outcome::Err(invalid("journal restore exceeds object, receipt or buffer limit"));
    }
    let entries = match journal.get_transfer_entries(transfer_id) {
        Outcome::Ok(entries) => entries,
        Outcome::Err(error) => return Outcome::Err(invalid(format!("journal restore: {error}"))),
        Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => return Outcome::Panicked(payload),
    };
    // Summary authentication covers these same immutable indexed entries. Bind
    // the selected identity as well as the length; equal-sized offers for other
    // objects must never turn one writer's receipts into another object's data.
    let mut offered = None;
    for entry in &entries {
        if let JournalRecord::Offer { object_id, manifest_root, total_size: size, .. } = &entry.record {
            let identity = (object_id, manifest_root);
            if *size != total_size || offered.is_some_and(|previous| previous != identity) {
                return Outcome::Err(invalid("journal restore offer identity or root conflict"));
            }
            offered = Some(identity);
        }
    }
    let Some((object_id, _)) = offered else {
        return Outcome::Err(invalid("journal restore has no authenticated offer"));
    };
    Outcome::Ok(RestorePlan {
        object_id: object_id.clone(),
        total_size,
        chunks: summary.durable_chunks,
    })
}

// This guard lives inside the blocking job. It never performs cleanup on the
// scheduler thread, and never owns the caller's source inode or source pathname.
struct RestoreStaging(Option<SparseWriter>);

impl RestoreStaging {
    fn writer(&self) -> &SparseWriter {
        self.0.as_ref().expect("restore staging is owned until success")
    }

    fn fail(&mut self, error: SparseWriterError) -> SparseWriterError {
        let path = self.writer().lock_state().temp_path.clone();
        let cleanup = self.writer().cancel_blocking();
        // An ordinary cleanup failure retains the path as evidence. Do not
        // silently retry it from Drop after reporting that retained path.
        drop(self.0.take());
        match cleanup {
            Outcome::Ok(()) => error,
            failure => SparseWriterError::WriteFailed(format!(
                "{error}; restore cleanup did not complete ({failure:?}); retained staging: {path:?}",
            )),
        }
    }
}

impl Drop for RestoreStaging {
    fn drop(&mut self) {
        if let Some(writer) = &self.0 {
            // Ordinary failures report cleanup diagnostics above. Unwinding or
            // a checkpoint failure has no domain result in which to put them.
            let _ = writer.cancel_blocking();
        }
    }
}

fn restore_file(
    mut source: File,
    final_path: PathBuf,
    config: SparseWriterConfig,
    plan: RestorePlan,
    mut checkpoint: impl FnMut() -> io::Result<()>,
) -> io::Result<Outcome<SparseWriter, SparseWriterError>> {
    checkpoint()?;
    let metadata = match source.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Ok(Outcome::Err(invalid(format!("restore source metadata: {error}")))),
    };
    if !metadata.is_file() || metadata.len() > plan.total_size
        || plan.chunks.iter().any(|chunk| chunk.chunk_offset.checked_add(chunk.chunk_size)
            .is_none_or(|end| end > metadata.len()))
    {
        return Ok(Outcome::Err(invalid("restore source is not a compatible whole-object file")));
    }
    let max_chunk = plan.chunks.iter().map(|chunk| chunk.chunk_size).max().unwrap_or(0);
    let max_chunk = usize::try_from(max_chunk)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "restore chunk exceeds address space"))?;
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(max_chunk)
        .map_err(|error| io::Error::other(format!("restore buffer allocation: {error}")))?;
    checkpoint()?;
    let writer = match SparseWriter::new_blocking(plan.object_id, final_path, config) {
        Outcome::Ok(writer) => writer,
        Outcome::Err(error) => return Ok(Outcome::Err(error)),
        Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
        Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
    };
    let mut staging = RestoreStaging(Some(writer));
    if let Err(error) = staging.writer().set_expected_size(plan.total_size) {
        return Ok(Outcome::Err(staging.fail(error)));
    }
    for chunk in plan.chunks {
        checkpoint()?;
        // The admitted length fits usize and the one reserved allocation.
        buffer.resize(chunk.chunk_size as usize, 0);
        if let Err(error) = source.seek(SeekFrom::Start(chunk.chunk_offset)) {
            return Ok(Outcome::Err(staging.fail(invalid(format!("restore source seek: {error}")))));
        }
        let mut filled = 0;
        while filled < buffer.len() {
            checkpoint()?;
            let end = (filled + (buffer.len() - filled).min(8192)).min(buffer.len());
            match source.read(&mut buffer[filled..end]) {
                Ok(0) => return Ok(Outcome::Err(staging.fail(invalid("restore source was truncated")))),
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Ok(Outcome::Err(staging.fail(invalid(format!("restore source read: {error}"))))),
            }
        }
        let actual: [u8; 32] = Sha256::digest(&buffer).into();
        if actual != chunk.chunk_hash {
            return Ok(Outcome::Err(staging.fail(invalid(format!(
                "restore payload hash mismatch at offset {} size {}", chunk.chunk_offset, chunk.chunk_size,
            )))));
        }
        checkpoint()?;
        match staging.writer().write_chunk_blocking(chunk.chunk_offset, &buffer, WriteOptions::default()) {
            Outcome::Ok(_) => {}
            Outcome::Err(error) => return Ok(Outcome::Err(staging.fail(error))),
            Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
            Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
        }
    }
    Ok(Outcome::Ok(staging.0.take().expect("successful restore retains its writer")))
}

#[cfg(test)]
mod tests;
