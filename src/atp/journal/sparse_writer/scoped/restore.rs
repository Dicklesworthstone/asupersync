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

// The producer and physical recovery share one compiled source boundary.
mod checkpoint {
//! Produce the durable receipt chain consumed by physical writer restoration.

use super::super::ScopedSparseWriter;
use crate::atp::journal::append_journal::JournalError;
use crate::atp::journal::sparse_writer::{SparseWriter, SparseWriterError, VerificationState};
use crate::atp::journal::{
    AppendJournal, JournalCheckpoint, JournalCheckpointReport, JournalCheckpointRequest,
    JournalRecord, TransferResumeStatus,
};
use crate::atp::object::ObjectKind;
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::fs::scoped::ScopedFsError;
use crate::security::AuthenticationTag;
use crate::types::Outcome;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

// Preserve all four journal outcomes instead of treating interruption as an
// empty history or translating an actual effect into a cancellation guess.
macro_rules! journal_value {
    ($expression:expr) => {
        match $expression {
            Outcome::Ok(value) => value,
            Outcome::Err(error) => return Outcome::Err(journal_error(error)),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
    };
}

impl ScopedSparseWriter {
    /// Persist reusable staging progress into the journal used by restoration.
    ///
    /// Ownership of the journal moves into the same region-owned job as the
    /// writer's admission permit. The returned report gives it back on success
    /// AND ordinary domain refusal, including its fenced state after uncertain
    /// storage. An outer gateway error or abandoned result drops that owner;
    /// reopen its existing files, never assume that no record reached storage.
    /// Do not use another writer for the journal directory concurrently.
    ///
    /// This validates the expected file identity, root, length, receipt bounds
    /// and existing history before effects. It rehashes every local write receipt,
    /// flushes/synchronizes the staging inode and, on Unix, its directory, then
    /// appends missing Received -> Verified -> Written records and synchronizes
    /// the journal, even with automatic force_sync disabled. Identical checkpoints
    /// add no records. Interrupted chains can continue from their last valid phase.
    ///
    /// A chunk receipt authenticates locally retained bytes, not an independently
    /// authorized remote object. This does not promote content verification,
    /// publish a destination, acknowledge a peer, or persist a commit decision.
    /// Fresh final manifest verification is still required. The snapshot's path
    /// must be retained by the application's trusted recovery catalog; journal
    /// path strings do not grant restoration authority.
    ///
    /// The started job drains as one operation, including hashing and compaction;
    /// it has no additional mid-operation cancellation checkpoints. Bounds cover
    /// object/receipt sizes, not total journal history or a syscall deadline.
    /// External mutation and hostile parent paths are outside this contract.
    /// Non-Unix directory-entry durability remains the existing platform limit.
    pub async fn checkpoint_to_journal<Caps>(
        &self,
        cx: &Cx<Caps>,
        request: JournalCheckpointRequest,
    ) -> Result<JournalCheckpointReport, ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.checkpoint_with(cx, request, sync_staging).await
    }

    // Inject only the physical barrier, not receipt selection or journal writes.
    // Tests gate/fail the actual owned path without another filesystem executor.
    async fn checkpoint_with<Caps, F>(
        &self,
        cx: &Cx<Caps>,
        request: JournalCheckpointRequest,
        sync: F,
    ) -> Result<JournalCheckpointReport, ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&File, &Path) -> io::Result<()> + Send + 'static,
    {
        let permit = self.reserve(cx).await?;
        let writer = Arc::clone(&self.writer);
        cx.scoped_fs()
            .run_io(move |_| {
                let _permit = permit;
                let JournalCheckpointRequest {
                    mut journal, transfer_id, manifest, limits, timestamp,
                } = request;
                let outcome = checkpoint_writer(
                    &writer, &mut journal, &transfer_id, &manifest, limits, timestamp, sync,
                );
                Ok(JournalCheckpointReport { journal, outcome })
            })
            .await
    }
}

fn invalid(message: impl Into<String>) -> SparseWriterError {
    SparseWriterError::VerificationFailed(message.into())
}

fn journal_error(error: JournalError) -> SparseWriterError {
    SparseWriterError::WriteFailed(format!("checkpoint journal: {error}"))
}

fn sync_staging(file: &File, path: &Path) -> io::Result<()> {
    file.sync_all()?;
    #[cfg(unix)]
    {
        let parent = path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn checkpoint_writer(
    writer: &SparseWriter,
    journal: &mut AppendJournal,
    transfer_id: &str,
    manifest: &crate::atp::manifest::Manifest,
    limits: crate::atp::journal::JournalRestoreLimits,
    timestamp: u64,
    sync: impl FnOnce(&File, &Path) -> io::Result<()>,
) -> Outcome<JournalCheckpoint, SparseWriterError> {
    let _operation = writer.operation.lock();
    let mut state = writer.lock_state();
    if let Err(error) = SparseWriter::require_accepting(&state) {
        return Outcome::Err(error);
    }
    if transfer_id.is_empty() || limits.max_chunk_bytes == 0 {
        return Outcome::Err(invalid("checkpoint requires a transfer ID and nonzero receipt limit"));
    }
    if let Err(error) = manifest.validate() {
        return Outcome::Err(invalid(format!("checkpoint manifest: {error}")));
    }
    let Some(object) = manifest.objects.get(&state.object_id) else {
        return Outcome::Err(invalid("checkpoint manifest does not contain the selected file"));
    };
    let Some(length) = object.size_bytes else {
        return Outcome::Err(invalid("checkpoint requires the offered file length"));
    };
    if object.id != state.object_id || object.kind != ObjectKind::FileObject
        || state.expected_size != Some(length)
    {
        return Outcome::Err(invalid("checkpoint file identity or expected length mismatch"));
    }
    if length > limits.max_bytes
        || u64::try_from(state.written_chunks.len()).map_or(true, |n| n > u64::from(limits.max_chunks))
        || state.written_chunks.values().any(|chunk| {
            chunk.size == 0
                || usize::try_from(chunk.size).map_or(true, |size| size > limits.max_chunk_bytes)
                || chunk.offset.checked_add(chunk.size).is_none_or(|end| end > length)
        })
    {
        return Outcome::Err(invalid("checkpoint exceeds object or receipt bounds"));
    }

    // Summary authentication covers the same immutable entries inspected below.
    // A terminal/uncertain history cannot be rebound to an accepting writer.
    let summary = journal_value!(journal.get_resume_summary(transfer_id));
    if !matches!(summary.status, TransferResumeStatus::Unknown | TransferResumeStatus::Resumable) {
        return Outcome::Err(invalid("checkpoint refuses a terminal or commit-intent journal"));
    }
    let entries = journal_value!(journal.get_transfer_entries(transfer_id));
    let mut offered = false;
    let mut phases = BTreeMap::<u64, u8>::new();
    for entry in &entries {
        let (offset, size, hash, phase) = match &entry.record {
            JournalRecord::Offer { object_id, manifest_root, total_size, .. } => {
                if object_id != &state.object_id || manifest_root != &manifest.merkle_root || *total_size != length {
                    return Outcome::Err(invalid("checkpoint conflicts with the journal's offered object"));
                }
                offered = true;
                continue;
            }
            JournalRecord::ChunkReceived { chunk_offset, chunk_size, chunk_hash, .. } =>
                (*chunk_offset, *chunk_size, Some(chunk_hash), 1),
            JournalRecord::ChunkVerified { chunk_offset, chunk_size, verified_hash, .. } =>
                (*chunk_offset, *chunk_size, Some(verified_hash), 2),
            JournalRecord::ChunkWritten { chunk_offset, chunk_size, .. } =>
                (*chunk_offset, *chunk_size, None, 3),
            JournalRecord::Accept { .. } | JournalRecord::ProofDigest { .. } => continue,
            _ => return Outcome::Err(invalid("checkpoint history contains an unsupported transfer transition")),
        };
        let Some(chunk) = state.written_chunks.get(&offset) else {
            return Outcome::Err(invalid("checkpoint journal names bytes absent from this writer"));
        };
        if !offered || chunk.size != size || hash.is_some_and(|hash| *hash != chunk.hash) {
            return Outcome::Err(invalid("checkpoint journal receipt differs from this writer"));
        }
        let previous = phases.get(&offset).copied().unwrap_or(0);
        // Exact repeated phases are harmless. Missing prerequisites, reordered
        // phases and regressions cannot become reusable progress by set union.
        if phase < previous || phase > previous + 1 {
            return Outcome::Err(invalid("checkpoint journal receipt order is inconsistent"));
        }
        phases.insert(offset, phase);
    }
    if !entries.is_empty() && !offered {
        return Outcome::Err(invalid("checkpoint cannot adopt history without an offer"));
    }

    // No journal mutation precedes acquiring and validating the actual staging
    // descriptor. Empty/no-progress checkpoints still retain a real source inode.
    if let Err(error) = writer.ensure_temp_file_open_locked(&mut state) {
        return Outcome::Err(error);
    }
    let Some(path) = state.temp_path.clone() else {
        return Outcome::Err(SparseWriterError::NoTempFile);
    };
    let checked = (|| -> Result<(), SparseWriterError> {
        let file = state.temp_file.as_mut().ok_or(SparseWriterError::NoTempFile)?;
        file.flush().map_err(|error| SparseWriterError::SyncFailed(error.to_string()))?;
        let metadata = file.metadata().map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file() || metadata.len() > length {
            return Err(invalid("checkpoint staging has an incompatible file length"));
        }
        let mut reader = file.try_clone().map_err(|error| invalid(error.to_string()))?;
        for chunk in state.written_chunks.values() {
            if chunk.offset.checked_add(chunk.size).is_none_or(|end| end > metadata.len()) {
                return Err(invalid("checkpoint staging was truncated"));
            }
            if SparseWriter::hash_file_range(&mut reader, chunk.offset, chunk.size)? != chunk.hash {
                return Err(invalid(format!("checkpoint staging hash mismatch at offset {}", chunk.offset)));
            }
        }
        Ok(())
    })();
    if let Err(error) = checked {
        state.verification_state = VerificationState::Failed { reason: error.to_string() };
        return Outcome::Err(error);
    }
    let Some(file) = state.temp_file.as_ref() else {
        return Outcome::Err(SparseWriterError::NoTempFile);
    };
    if let Err(error) = sync(file, &path) {
        return Outcome::Err(SparseWriterError::SyncFailed(error.to_string()));
    }
    for chunk in state.written_chunks.values_mut() {
        chunk.synced = true;
    }

    // The complete physical barrier precedes even the offer. Partial journal
    // appends can only expose already-synchronized bytes. AppendJournal fences
    // uncertain writes and carries these original records through compaction.
    if !offered {
        journal_value!(journal.append(JournalRecord::Offer {
            transfer_id: transfer_id.to_owned(), object_id: state.object_id.clone(),
            manifest_root: manifest.merkle_root.clone(), total_size: length, timestamp,
            auth_tag: AuthenticationTag::zero(),
        }));
    }
    for (offset, chunk) in &state.written_chunks {
        let phase = phases.get(offset).copied().unwrap_or(0);
        if phase < 1 {
            journal_value!(journal.append(JournalRecord::ChunkReceived {
                transfer_id: transfer_id.to_owned(), chunk_offset: *offset, chunk_size: chunk.size,
                chunk_hash: chunk.hash, timestamp, auth_tag: AuthenticationTag::zero(),
            }));
        }
        if phase < 2 {
            journal_value!(journal.append(JournalRecord::ChunkVerified {
                transfer_id: transfer_id.to_owned(), chunk_offset: *offset, chunk_size: chunk.size,
                verified_hash: chunk.hash, timestamp, auth_tag: AuthenticationTag::zero(),
            }));
        }
        if phase < 3 {
            journal_value!(journal.append(JournalRecord::ChunkWritten {
                transfer_id: transfer_id.to_owned(), chunk_offset: *offset, chunk_size: chunk.size,
                // Diagnostic only. Restore always requires application-selected
                // paths/descriptors; this lossy spelling is never open authority.
                file_path: path.to_string_lossy().into_owned(), timestamp,
                auth_tag: AuthenticationTag::zero(),
            }));
        }
    }
    journal_value!(journal.flush());
    let summary = journal_value!(journal.get_resume_summary(transfer_id));
    Outcome::Ok(JournalCheckpoint { source_path: path, summary })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::journal::{
        CommitPolicy, FsyncPolicy, JournalConfig, JournalRestoreLimits, JournalRestoreRequest,
        ScopedReceiveOptions, SparseWriterConfig, WriteOptions,
    };
    use crate::atp::manifest::{Manifest, MerkleRoot};
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::channel::oneshot;
    use crate::cx::ChildRegionSpec;
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use crate::security::AuthKey;
    use crate::types::CancelKind;
    use std::future::{Future, poll_fn};
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::Duration;

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
        builder.blocking_threads(1, 2).build().unwrap()
    }

    fn drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    fn limits() -> JournalRestoreLimits {
        JournalRestoreLimits { max_bytes: 64, max_chunks: 16, max_chunk_bytes: 8 }
    }

    fn journal_config(base: &Path) -> JournalConfig {
        JournalConfig {
            base_dir: base.join("journal"), force_sync: false,
            max_journal_size: u64::MAX, recent_entries_limit: 1,
            ..JournalConfig::default()
        }
    }

    fn journal(base: &Path) -> AppendJournal {
        AppendJournal::new(journal_config(base), AuthKey::from_seed(42)).unwrap()
    }

    fn request(journal: AppendJournal, manifest: Arc<Manifest>) -> JournalCheckpointRequest {
        JournalCheckpointRequest {
            journal, transfer_id: "checkpoint".to_owned(), manifest, limits: limits(), timestamp: 17,
        }
    }

    async fn writer(cx: &Cx, base: &Path, data: &[u8]) -> (ScopedSparseWriter, Arc<Manifest>) {
        let object = Object::file(data.to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
        let writer = ScopedSparseWriter::new(cx, id, base.join("destination"), SparseWriterConfig {
            enable_preallocation: false, fsync_policy: FsyncPolicy::Never,
            ..SparseWriterConfig::default()
        }).await.unwrap().unwrap();
        writer.set_expected_size(cx, data.len() as u64).await.unwrap().unwrap();
        (writer, manifest)
    }

    #[test]
    fn produced_checkpoint_reopens_restores_and_receives_only_the_missing_suffix() {
        for workers in [1, 2] {
            for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (writer, manifest) = writer(&cx, directory.path(), b"abcdefgh").await;
                    writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                    let report = writer.checkpoint_to_journal(&cx, request(journal(directory.path()), manifest.clone())).await.unwrap();
                    let saved = report.outcome.unwrap();
                    assert_eq!(saved.summary.durable_bytes, 4);
                    assert_eq!(saved.summary.contiguous_prefix_bytes, 4);
                    assert_eq!(saved.summary.total_size, Some(8));
                    assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().verification_state, VerificationState::Pending);
                    assert!(!directory.path().join("destination").exists());
                    let before = report.journal.get_stats().sequence;
                    assert_eq!(before, 4); // Offer and the ordered three-record receipt.
                    let mut again = writer.checkpoint_to_journal(&cx, request(report.journal, manifest.clone())).await.unwrap();
                    assert_eq!(again.outcome.unwrap().summary, saved.summary);
                    assert_eq!(again.journal.get_stats().sequence, before);
                    again.journal.compact().unwrap();
                    drop(again.journal);
                    drop(writer);
                    let destination = directory.path().join("restored");
                    let restored = ScopedSparseWriter::restore_from_storage(&cx, JournalRestoreRequest {
                        journal_config: journal_config(directory.path()), auth_key: AuthKey::from_seed(42),
                        transfer_id: "checkpoint".to_owned(), source_path: saved.source_path.clone(),
                        final_path: destination.clone(), writer_config: SparseWriterConfig {
                            enable_preallocation: false, commit_policy: policy, ..SparseWriterConfig::default()
                        }, limits: limits(),
                    }).await.unwrap().unwrap();
                    assert_eq!(restored.checked_receive_offset(&cx).await.unwrap().unwrap(), 4);
                    let mut receiving = restored.resume_exact_at(&cx, b"efghNEXT".as_slice(), manifest,
                        ScopedReceiveOptions { max_bytes: 8, max_chunks: 8, chunk_size: 2 }, 4).unwrap();
                    assert_eq!(receiving.wait().await.unwrap().unwrap(), destination);
                    assert_eq!(receiving.take_source().unwrap(), b"NEXT");
                    assert_eq!(std::fs::read(destination).unwrap(), b"abcdefgh");
                    assert_eq!(std::fs::read(saved.source_path).unwrap(), b"abcd");
                });
                drained(&runtime);
            }
        }
    }

    #[test]
    fn empty_and_sparse_checkpoints_keep_extent_and_never_invent_missing_bytes() {
        for data in [b"".as_slice(), b"abcdefghijkl".as_slice()] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = writer(&cx, directory.path(), data).await;
                if !data.is_empty() {
                    writer.write_chunk(&cx, 8, b"ijkl".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                    writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                }
                let report = writer.checkpoint_to_journal(&cx, request(journal(directory.path()), manifest)).await.unwrap();
                let saved = report.outcome.unwrap();
                assert!(saved.source_path.is_file());
                assert_eq!(saved.summary.total_size, Some(data.len() as u64));
                assert_eq!(saved.summary.durable_bytes, if data.is_empty() { 0 } else { 8 });
                assert_eq!(saved.summary.contiguous_prefix_bytes, if data.is_empty() { 0 } else { 4 });
                let offsets: Vec<_> = saved.summary.durable_chunks.iter().map(|chunk| chunk.chunk_offset).collect();
                assert_eq!(offsets, if data.is_empty() { vec![] } else { vec![0, 8] });
                assert!(matches!(writer.commit(&cx).await,
                    Ok(Outcome::Err(SparseWriterError::NotVerified | SparseWriterError::IncompleteData))));
                assert!(!directory.path().join("destination").exists());
            });
            drained(&runtime);
        }
    }

    #[test]
    fn incomplete_receipt_chains_are_completed_once_without_replaying_old_phases() {
        for retained in 1..=4 {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = writer(&cx, directory.path(), b"data").await;
                writer.write_chunk(&cx, 0, b"data".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                let report = writer.checkpoint_to_journal(&cx, request(journal(directory.path()), manifest.clone())).await.unwrap();
                report.outcome.unwrap();
                let entries = report.journal.get_transfer_entries("checkpoint").unwrap();
                let partial_base = directory.path().join("partial");
                let mut partial = journal(&partial_base);
                for entry in entries.iter().take(retained) {
                    partial.append(entry.record.clone()).unwrap();
                }
                partial.flush().unwrap();
                let report = writer.checkpoint_to_journal(&cx, request(partial, manifest)).await.unwrap();
                assert_eq!(report.outcome.unwrap().summary.durable_bytes, 4);
                assert_eq!(report.journal.get_stats().sequence, 4);
                assert_eq!(report.journal.get_transfer_entries("checkpoint").unwrap().len(), 4);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn physical_barrier_failure_and_panic_cannot_append_a_progress_record() {
        for panics in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = writer(&cx, directory.path(), b"data").await;
                writer.write_chunk(&cx, 0, b"data".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                let result = writer.checkpoint_with(&cx, request(journal(directory.path()), manifest.clone()), move |_, _| {
                    assert!(!panics, "checkpoint barrier panic");
                    Err(io::Error::other("checkpoint barrier failure"))
                }).await;
                if panics {
                    assert!(matches!(result, Err(ScopedFsError::Join(crate::runtime::JoinError::Panicked(_)))));
                } else {
                    let report = result.unwrap();
                    assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::SyncFailed(message))
                        if message == "checkpoint barrier failure"));
                    assert_eq!(report.journal.get_stats().sequence, 0);
                }
                assert_eq!(std::fs::read_dir(journal_config(directory.path()).base_dir).unwrap().count(), 0);
                assert_eq!(writer.admission.available_permits(), 1);
                assert!(writer.writer.lock_state().written_chunks.values().all(|chunk| !chunk.synced));
                let report = writer.checkpoint_to_journal(&cx, request(journal(directory.path()), manifest)).await.unwrap();
                assert_eq!(report.outcome.unwrap().summary.durable_bytes, 4);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn changed_payload_refuses_before_journal_effects_and_invalidates_old_verification() {
        for changed in [b"bad!".as_slice(), b"cut".as_slice(), b"larger".as_slice()] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = writer(&cx, directory.path(), b"data").await;
                writer.write_chunk(&cx, 0, b"data".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                writer.verify(&cx, manifest.clone()).await.unwrap().unwrap();
                let path = writer.writer.lock_state().temp_path.clone().unwrap();
                cx.scoped_fs().write(path, changed.to_vec()).await.unwrap();
                let report = writer.checkpoint_to_journal(&cx, request(journal(directory.path()), manifest)).await.unwrap();
                assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                assert_eq!(report.journal.get_stats().sequence, 0);
                assert!(matches!(writer.get_stats(&cx).await.unwrap().unwrap().verification_state, VerificationState::Failed { .. }));
                assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
            });
            drained(&runtime);
        }
    }

    #[test]
    fn limits_terminal_history_and_conflicting_identity_refuse_before_staging() {
        for case in 0..6 {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = writer(&cx, directory.path(), b"data").await;
                let mut request = request(journal(directory.path()), manifest);
                match case {
                    0 => request.limits.max_bytes = 3,
                    1 => request.limits.max_chunk_bytes = 0,
                    2 => request.transfer_id.clear(),
                    3 => { request.journal.append(JournalRecord::Cancellation {
                        transfer_id: request.transfer_id.clone(), reason: "stop".to_owned(), timestamp: 1,
                        auth_tag: AuthenticationTag::zero(),
                    }).unwrap(); }
                    4 => { request.journal.append(JournalRecord::Offer {
                        transfer_id: request.transfer_id.clone(), object_id: writer.writer.lock_state().object_id.clone(),
                        manifest_root: MerkleRoot::new([99; 32]), total_size: 4, timestamp: 1,
                        auth_tag: AuthenticationTag::zero(),
                    }).unwrap(); }
                    5 => { request.journal.append(JournalRecord::Accept {
                        transfer_id: request.transfer_id.clone(), peer_id: "no-offer".to_owned(), timestamp: 1,
                        auth_tag: AuthenticationTag::zero(),
                    }).unwrap(); }
                    _ => unreachable!(),
                }
                let sequence = request.journal.get_stats().sequence;
                let report = writer.checkpoint_to_journal(&cx, request).await.unwrap();
                assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                assert_eq!(report.journal.get_stats().sequence, sequence);
                assert!(writer.writer.lock_state().temp_file.is_none());
                assert!(!directory.path().join("destination").exists());
            });
            drained(&runtime);
        }
    }

    #[test]
    fn dropped_checkpoint_wait_keeps_journal_and_writer_owned_until_region_drain() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = writer(&cx, directory.path(), b"data").await;
                writer.write_chunk(&cx, 0, b"data".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let child = region.cx();
                let (started, mut start) = oneshot::channel();
                let (release, wait) = mpsc::channel();
                let mut checkpointing = Box::pin(writer.checkpoint_with(&child,
                    request(journal(directory.path()), manifest), move |file, path| {
                        started.send_blocking(()).unwrap();
                        wait.recv_timeout(Duration::from_secs(10)).unwrap();
                        sync_staging(file, path)
                    }));
                poll_fn(|task| { assert!(checkpointing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                start.recv(&cx).await.unwrap();
                drop(checkpointing);
                assert_eq!(writer.admission.available_permits(), 0);
                let mut closing = Box::pin(region.close());
                poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                assert_eq!(std::fs::read_dir(journal_config(directory.path()).base_dir).unwrap().count(), 0);
                release.send(()).unwrap();
                closing.await.unwrap();
                assert_eq!(writer.admission.available_permits(), 1);
                let reopened = journal(directory.path());
                assert_eq!(reopened.get_resume_summary("checkpoint").unwrap().durable_bytes, 4);
                assert!(!directory.path().join("destination").exists());
            });
            drained(&runtime);
        }
    }

    #[test]
    fn precancelled_checkpoint_is_send_and_cannot_create_a_generation_or_staging() {
        fn assert_send<T: Send>(_: &T) {}
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = writer(&cx, directory.path(), b"data").await;
            let unpolled = writer.checkpoint_to_journal(&cx, request(journal(directory.path()), manifest.clone()));
            assert_send(&unpolled);
            drop(unpolled);
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            child.cancel_with(CancelKind::User, Some("before checkpoint"));
            assert!(matches!(writer.checkpoint_to_journal(&child, request(journal(directory.path()), manifest)).await,
                Err(ScopedFsError::Checkpoint(_))));
            assert!(writer.writer.lock_state().temp_file.is_none());
            assert_eq!(std::fs::read_dir(journal_config(directory.path()).base_dir).unwrap().count(), 0);
            region.close().await.unwrap();
        });
        drained(&runtime);
    }
}
}
