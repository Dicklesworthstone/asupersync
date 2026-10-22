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

// Completion recovery belongs beside finalization, but NEVER calls a publisher.
// Keep the original finalization implementation and its test module unchanged.
mod completion_recovery {
    use super::{Cx, File, ScopedSparseWriter, SparseWriter, SparseWriterError};
    use crate::atp::journal::{
        AppendJournal, JournalCommitRecoveryReport, JournalCommitRecoveryRequest,
        JournalRecord, TransferResumeStatus,
    };
    use crate::atp::object::ObjectKind;
    use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
    use crate::fs::scoped::ScopedFsError;
    use crate::security::AuthenticationTag;
    use crate::types::Outcome;
    use sha2::{Digest, Sha256};
    use std::fs::{Metadata, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom};
    use std::path::{Component, Path, PathBuf};

    macro_rules! value {
        ($expression:expr) => {
            match $expression {
                Outcome::Ok(value) => value,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        };
    }

    impl ScopedSparseWriter {
        /// Settle an interrupted commit by checking its already-existing destination.
        ///
        /// This is recovery after draining the previous writer, not a retry on a
        /// live/sealed writer. The application supplies the trusted absolute path:
        /// CommitIntent does not encode one. Own that path, its ancestry and the
        /// journal exclusively until the operation retires. No live writer's FIFO
        /// permit can substitute for exclusive ownership after a process restart.
        ///
        /// One existing region-owned filesystem job authenticates the complete
        /// transfer history, checks the selected file and optional pinned chunks,
        /// synchronizes the actual descriptor and Unix parent, then appends and
        /// synchronizes a matching CommitComplete. No source is copied, renamed,
        /// truncated, removed, quarantined, or republished. Missing/corrupt output
        /// leaves the intent unresolved; it never authorizes retransmission.
        ///
        /// The bounded whole-file digest uses the same content-ID domain as the
        /// canonical writer. Chunk digests and exact chunk-only coverage use its
        /// existing helpers. Partial chunk hints cannot replace full authentication.
        /// At most the admitted file length is read per whole-file pass; descriptors
        /// are bounded and nonoverlapping. Scratch space is fixed at 8 KiB. Existing
        /// manifest/journal allocations and total history are not bounded here.
        ///
        /// Every successful call freshly checks the bytes and persists a new
        /// matching completion, including after reopening an old completion. Reading
        /// that record then flushing an unopened journal is not a fresh sync barrier.
        /// Existing matching completions are allowed; conflicting terminal history
        /// refuses before opening the destination. This proves current satisfaction
        /// of the application's file expectation, not the earlier publisher's return
        /// value, delivery of peer Proof, or who originally created the destination.
        ///
        /// Final symlinks/nonregular files are refused. Unix opens additionally use
        /// O_NOFOLLOW/O_NONBLOCK and compare descriptor/path inode identity. Metadata
        /// checks detect observed replacement/modification, not hostile concurrent
        /// mutation or parent-path races. Non-Unix identity checks are weaker and
        /// parent-directory durability retains the existing platform limitation.
        /// A host refusing sync on the read-only descriptor refuses completion.
        ///
        /// Once started this job drains rather than rolling back on cancellation.
        /// Ordinary failures return the journal with independent verified/synced/
        /// persisted flags. A lost gateway result or abandoned wait requires region
        /// drain and reopening retained storage, never assuming no records reached it.
        pub async fn reconcile_committed_destination<Caps>(
            cx: &Cx<Caps>,
            request: JournalCommitRecoveryRequest,
        ) -> Result<JournalCommitRecoveryReport, ScopedFsError>
        where
            Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        {
            Self::reconcile_destination_with(cx, request, sync_destination).await
        }

        // Tests may fail/gate only this actual storage barrier, not history,
        // content checks, terminal persistence, or the region-owned gateway.
        async fn reconcile_destination_with<Caps, S>(
            cx: &Cx<Caps>,
            mut request: JournalCommitRecoveryRequest,
            sync: S,
        ) -> Result<JournalCommitRecoveryReport, ScopedFsError>
        where
            Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
            S: FnOnce(&File, &Path) -> io::Result<()> + Send + 'static,
        {
            cx.scoped_fs().run_io(move |_| {
                let mut content_verified = false;
                let mut destination_synced = false;
                let mut completion_persisted = false;
                let outcome = reconcile(
                    &mut request, &mut content_verified, &mut destination_synced,
                    &mut completion_persisted, sync,
                );
                Ok(JournalCommitRecoveryReport {
                    journal: request.journal, content_verified, destination_synced,
                    completion_persisted, outcome,
                })
            }).await
        }
    }

    fn invalid(message: impl Into<String>) -> SparseWriterError {
        SparseWriterError::VerificationFailed(message.into())
    }

    fn journal_error(error: crate::atp::journal::append_journal::JournalError) -> SparseWriterError {
        SparseWriterError::WriteFailed(format!("completion recovery journal: {error}"))
    }

    fn preflight(request: &JournalCommitRecoveryRequest) -> Result<u64, SparseWriterError> {
        if request.transfer_id.is_empty() || request.transfer_id.len() > 4096 {
            return Err(invalid("completion recovery requires a bounded nonempty transfer ID"));
        }
        if !request.destination.is_absolute() || request.destination.to_str().is_none()
            || request.destination.file_name().is_none()
            || request.destination.components().any(|part| matches!(part, Component::ParentDir))
        {
            return Err(invalid("completion recovery requires a trusted absolute UTF-8 file path without parent traversal"));
        }
        if let Some(expected) = &request.expected_chunk_commitment {
            expected.verify(&request.manifest)
                .map_err(|error| invalid(format!("completion recovery chunk commitment: {error}")))?;
        } else {
            request.manifest.validate()
                .map_err(|error| invalid(format!("completion recovery manifest: {error}")))?;
        }
        let object = request.manifest.objects.get(&request.object_id)
            .ok_or_else(|| invalid("completion recovery manifest omits selected file"))?;
        let length = object.size_bytes
            .ok_or_else(|| invalid("completion recovery needs the offered file length"))?;
        if object.id != request.object_id || object.kind != ObjectKind::FileObject {
            return Err(invalid("completion recovery selected file identity mismatch"));
        }
        if length > request.max_bytes
            || u64::try_from(object.chunk_boundaries.len())
                .map_or(true, |count| count > u64::from(request.max_manifest_chunks))
        {
            return Err(invalid("completion recovery exceeds file or descriptor bounds"));
        }
        if !request.object_id.is_content_addressed() && object.content_hash.is_none() {
            if request.expected_chunk_commitment.is_none() {
                return Err(invalid("chunk-only recovery requires an independently trusted commitment"));
            }
            SparseWriter::require_complete_manifest_chunks(&object.chunk_boundaries, length)
                .map_err(invalid)?;
        }
        for chunk in &object.chunk_boundaries {
            if chunk.byte_offset.checked_add(chunk.size_bytes).is_none_or(|end| end > length) {
                return Err(invalid("completion recovery chunk exceeds offered file length"));
            }
            if chunk.size_bytes == 0 {
                let empty: [u8; 32] = Sha256::digest(b"").into();
                if chunk.content_hash != empty {
                    return Err(invalid("completion recovery empty chunk hash mismatch"));
                }
            }
        }
        Ok(length)
    }

    fn validate_history(
        request: &JournalCommitRecoveryRequest,
        length: u64,
    ) -> Outcome<(), SparseWriterError> {
        // Authenticate every transfer record and require resolved journal storage
        // BEFORE interpreting its ordered history. A last-terminal-wins summary
        // alone cannot hide an earlier cancellation, rollback or changed target.
        let summary = value!(request.journal.get_resume_summary(&request.transfer_id)
            .map_err(journal_error));
        if !matches!(summary.status,
            TransferResumeStatus::CommitIntentPending | TransferResumeStatus::Committed { .. })
        {
            return Outcome::Err(invalid("completion recovery requires existing commit intent"));
        }
        let entries = value!(request.journal.get_transfer_entries(&request.transfer_id)
            .map_err(journal_error));
        let mut offered = false;
        let mut intent = false;
        let mut complete = false;
        let destination = request.destination.to_str().expect("preflight checked UTF-8 path");
        for entry in entries {
            match &entry.record {
                JournalRecord::Offer { object_id, manifest_root, total_size, .. }
                    if !intent && object_id == &request.object_id
                        && manifest_root == &request.manifest.merkle_root && *total_size == length =>
                {
                    offered = true;
                }
                JournalRecord::CommitIntent { final_manifest_root, .. }
                    if offered && !complete && final_manifest_root == &request.manifest.merkle_root =>
                {
                    intent = true;
                }
                JournalRecord::CommitComplete { final_path, committed_size, .. }
                    if intent && final_path == destination && *committed_size == length =>
                {
                    complete = true;
                }
                JournalRecord::Accept { .. } if offered && !intent => {}
                JournalRecord::ProofDigest { .. } if offered => {}
                JournalRecord::ChunkReceived { chunk_offset, chunk_size, .. }
                | JournalRecord::ChunkVerified { chunk_offset, chunk_size, .. }
                | JournalRecord::ChunkWritten { chunk_offset, chunk_size, .. }
                | JournalRecord::RepairDecode { chunk_offset, chunk_size, .. }
                    if offered && !intent && *chunk_size != 0
                        && chunk_offset.checked_add(*chunk_size).is_some_and(|end| end <= length) => {}
                _ => return Outcome::Err(invalid("completion recovery refuses conflicting transfer history")),
            }
        }
        if !offered || !intent {
            return Outcome::Err(invalid("completion recovery requires matching offer and intent"));
        }
        Outcome::Ok(())
    }

    fn open_destination(path: &Path, length: u64) -> Result<(File, Metadata), SparseWriterError> {
        let named = std::fs::symlink_metadata(path)
            .map_err(|error| SparseWriterError::FileOpen(error.to_string()))?;
        if !named.is_file() {
            return Err(invalid("completion recovery destination is not a regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Refuse final symlink substitution; avoid blocking if a regular
            // path was replaced by a FIFO between inspection and acquisition.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|error| SparseWriterError::FileOpen(error.to_string()))?;
        let metadata = file.metadata().map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file() || metadata.len() != length || !same_file_snapshot(&named, &metadata) {
            return Err(invalid("completion recovery destination length or identity changed"));
        }
        Ok((file, metadata))
    }

    fn same_file_snapshot(before: &Metadata, after: &Metadata) -> bool {
        if !after.is_file() || before.len() != after.len() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            before.dev() == after.dev() && before.ino() == after.ino()
                && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
        }
        #[cfg(not(unix))]
        {
            // This is NOT a portable inode-identity claim. Exclusive application
            // ownership remains mandatory on every platform, including Unix.
            matches!((before.modified(), after.modified()), (Ok(a), Ok(b)) if a == b)
        }
    }

    fn check_destination(file: &File, path: &Path, initial: &Metadata) -> Result<(), SparseWriterError> {
        let descriptor = file.metadata().map_err(|error| invalid(error.to_string()))?;
        let named = std::fs::symlink_metadata(path).map_err(|error| invalid(error.to_string()))?;
        if !same_file_snapshot(initial, &descriptor) || !same_file_snapshot(initial, &named) {
            return Err(invalid("completion recovery destination changed during verification"));
        }
        Ok(())
    }

    fn verify_destination(
        file: &mut File,
        request: &JournalCommitRecoveryRequest,
        length: u64,
    ) -> Result<(), SparseWriterError> {
        let object = request.manifest.objects.get(&request.object_id)
            .ok_or_else(|| invalid("completion recovery manifest omits selected file"))?;
        if object.content_hash.is_some() || request.object_id.is_content_addressed() {
            // Bound reads to the admitted length, even if an external writer grows
            // the inode. Use the SAME domain as SparseWriter's content-ID verifier.
            let mut hash = Sha256::new();
            if request.object_id.is_content_addressed() {
                hash.update(crate::atp::journal::sparse_writer::CONTENT_ID_DOMAIN);
            }
            file.seek(SeekFrom::Start(0)).map_err(|error| invalid(error.to_string()))?;
            let mut remaining = length;
            let mut buffer = [0_u8; 8192];
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..count]).map_err(|error| invalid(error.to_string()))?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            let actual: [u8; 32] = hash.finalize().into();
            if object.content_hash.is_some_and(|expected| expected != actual) {
                return Err(invalid("completion recovery manifest content hash mismatch"));
            }
            if request.object_id.is_content_addressed() && actual != *request.object_id.hash_bytes() {
                return Err(invalid("completion recovery content-addressed identity mismatch"));
            }
        }
        for chunk in &object.chunk_boundaries {
            if SparseWriter::hash_file_range(file, chunk.byte_offset, chunk.size_bytes)? != chunk.content_hash {
                return Err(invalid(format!("completion recovery manifest chunk {} hash mismatch", chunk.index)));
            }
        }
        Ok(())
    }

    fn sync_destination(file: &File, path: &Path) -> io::Result<()> {
        file.sync_all()?;
        #[cfg(unix)]
        File::open(path.parent().ok_or_else(|| io::Error::other("missing destination parent"))?)?.sync_all()?;
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    fn persist_completion(
        journal: &mut AppendJournal,
        record: JournalRecord,
    ) -> Outcome<(), SparseWriterError> {
        value!(journal.append(record).map_err(journal_error));
        journal.flush().map_err(journal_error)
    }

    fn reconcile(
        request: &mut JournalCommitRecoveryRequest,
        content_verified: &mut bool,
        destination_synced: &mut bool,
        completion_persisted: &mut bool,
        sync: impl FnOnce(&File, &Path) -> io::Result<()>,
    ) -> Outcome<PathBuf, SparseWriterError> {
        let length = match preflight(request) {
            Ok(length) => length,
            Err(error) => return Outcome::Err(error),
        };
        value!(validate_history(request, length));
        let (mut file, initial) = match open_destination(&request.destination, length) {
            Ok(opened) => opened,
            Err(error) => return Outcome::Err(error),
        };
        if let Err(error) = verify_destination(&mut file, request, length)
            .and_then(|()| check_destination(&file, &request.destination, &initial))
        {
            return Outcome::Err(error);
        }
        *content_verified = true;
        if let Err(error) = sync(&file, &request.destination) {
            return Outcome::Err(SparseWriterError::SyncFailed(error.to_string()));
        }
        if let Err(error) = check_destination(&file, &request.destination, &initial) {
            return Outcome::Err(error);
        }
        *destination_synced = true;
        let record = JournalRecord::CommitComplete {
            transfer_id: request.transfer_id.clone(),
            final_path: request.destination.to_str().expect("preflight checked UTF-8 path").to_owned(),
            committed_size: length, timestamp: request.timestamp,
            auth_tag: AuthenticationTag::zero(),
        };
        value!(persist_completion(&mut request.journal, record));
        *completion_persisted = true;
        Outcome::Ok(request.destination.clone())
    }

    #[cfg(all(test, unix))]
    mod tests {
        use super::*;
        use crate::atp::journal::{
            CommitPolicy, JournalCheckpointRequest, JournalConfig, JournalRestoreLimits,
            SparseWriterConfig, WriteOptions,
        };
        use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, Manifest, MerkleRoot};
        use crate::atp::manifest_chunk_commitment::ManifestChunkCommitment;
        use crate::atp::object::{ManifestId, MetadataPolicy, Object, ObjectGraph, ObjectId};
        use crate::channel::oneshot;
        use crate::cx::ChildRegionSpec;
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
        use crate::security::AuthKey;
        use crate::types::CancelKind;
        use std::future::{Future, poll_fn};
        use std::os::unix::fs::{MetadataExt, symlink};
        use std::sync::{Arc, mpsc};
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

        fn config(base: &Path) -> JournalConfig {
            JournalConfig {
                base_dir: base.join("journal"), force_sync: false,
                max_journal_size: u64::MAX, max_generations: 0,
                ..JournalConfig::default()
            }
        }

        fn expected(data: &[u8], style: u8) -> (ObjectId, Arc<Manifest>, Option<ManifestChunkCommitment>) {
            let object = Object::file(data.to_vec());
            let original = object.id.clone();
            let mut graph = ObjectGraph::new();
            graph.add_root(object).unwrap();
            let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
            let id = if style == 0 { original.clone() }
                else { ObjectId::manifest(ManifestId::from_manifest_bytes(b"recovered-file")) };
            let mut object = manifest.objects.remove(&original).unwrap();
            object.id = id.clone();
            if style != 0 {
                object.content_hash = (style == 1).then(|| Sha256::digest(data).into());
            }
            object.chunk_boundaries = data.chunks(3).enumerate().map(|(index, bytes)| ChunkBoundary {
                index: index as u32, byte_offset: (index * 3) as u64, size_bytes: bytes.len() as u64,
                content_hash: Sha256::digest(bytes).into(), strategy: ChunkStrategy::FixedSize,
                metadata: None,
            }).collect();
            manifest.objects.insert(id.clone(), object);
            manifest.roots = vec![id.clone()];
            manifest.merkle_root = MerkleRoot::from_manifest_components(
                &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
                &manifest.compression_policy, &manifest.encryption_policy, &manifest.capability_policy,
                &manifest.transform_order, &manifest.transform_proof_policy, &manifest.repair_groups,
            );
            manifest.validate().unwrap();
            let pin = (style == 2).then(|| ManifestChunkCommitment::from_manifest(&manifest).unwrap());
            (id, Arc::new(manifest), pin)
        }

        fn intent(manifest: &Manifest) -> JournalRecord {
            JournalRecord::CommitIntent {
                transfer_id: "recover-completion".to_owned(), final_manifest_root: manifest.merkle_root.clone(),
                timestamp: 2, auth_tag: AuthenticationTag::zero(),
            }
        }

        // Model the interrupted boundary using real checkpoint and publication:
        // persist Intent, publish through the canonical writer, omit Complete.
        // This is not a process-kill or power-loss simulation.
        async fn published_without_completion(
            cx: &Cx, base: &Path, data: &[u8], style: u8, policy: CommitPolicy,
        ) -> JournalCommitRecoveryRequest {
            let (id, manifest, pin) = expected(data, style);
            let path = base.join("destination");
            let writer = ScopedSparseWriter::new(cx, id.clone(), path.clone(), SparseWriterConfig {
                enable_preallocation: false, commit_policy: policy, ..SparseWriterConfig::default()
            }).await.unwrap().unwrap();
            writer.set_expected_size(cx, data.len() as u64).await.unwrap().unwrap();
            for (index, bytes) in data.chunks(3).enumerate() {
                writer.write_chunk(cx, (index * 3) as u64, bytes.to_vec(), WriteOptions::default())
                    .await.unwrap().unwrap();
            }
            let cfg = config(base);
            let journal = cx.scoped_fs().run_io(move |_| {
                Ok(AppendJournal::new(cfg, AuthKey::from_seed(42)).unwrap())
            }).await.unwrap();
            let checkpoint = writer.checkpoint_to_journal(cx, JournalCheckpointRequest {
                journal, transfer_id: "recover-completion".to_owned(), manifest: Arc::clone(&manifest),
                limits: JournalRestoreLimits { max_bytes: 64, max_chunks: 64, max_chunk_bytes: 64 },
                timestamp: 1,
            }).await.unwrap();
            checkpoint.outcome.unwrap();
            let record = intent(&manifest);
            let mut journal = checkpoint.journal;
            let journal = cx.scoped_fs().run_io(move |_| {
                journal.append(record).unwrap();
                journal.flush().unwrap();
                Ok(journal)
            }).await.unwrap();
            match pin {
                Some(pin) => writer.verify_and_commit_with_chunk_commitment(cx, Arc::clone(&manifest), pin)
                    .await.unwrap().unwrap(),
                None => writer.verify_and_commit(cx, Arc::clone(&manifest)).await.unwrap().unwrap(),
            };
            drop(writer);
            JournalCommitRecoveryRequest {
                journal, transfer_id: "recover-completion".to_owned(), object_id: id, manifest,
                expected_chunk_commitment: pin, destination: path, max_bytes: 64,
                max_manifest_chunks: 64, timestamp: 3,
            }
        }

        #[test]
        fn completion_recovery_reopens_actual_publication_without_replacing_its_inode() {
            for workers in [1, 2] {
                for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                    for style in 0..3 {
                        for data in [b"".as_slice(), b"abcdefgh".as_slice()] {
                            let directory = tempfile::tempdir().unwrap();
                            let runtime = runtime(workers);
                            runtime.block_on(async {
                                let cx = Cx::current().unwrap();
                                let mut request = published_without_completion(&cx, directory.path(), data, style, policy).await;
                                let original = std::fs::metadata(&request.destination).unwrap();
                                let path = request.destination.clone();
                                let id = request.object_id.clone();
                                let manifest = Arc::clone(&request.manifest);
                                let pin = request.expected_chunk_commitment;
                                let mut journal = request.journal;
                                let cfg = config(directory.path());
                                request.journal = cx.scoped_fs().run_io(move |_| {
                                    journal.compact().unwrap();
                                    drop(journal);
                                    let journal = AppendJournal::new(cfg, AuthKey::from_seed(42)).unwrap();
                                    assert_eq!(journal.get_resume_summary("recover-completion").unwrap().status,
                                        TransferResumeStatus::CommitIntentPending);
                                    Ok(journal)
                                }).await.unwrap();
                                let report = ScopedSparseWriter::reconcile_committed_destination(&cx, request).await.unwrap();
                                assert!(report.content_verified && report.destination_synced && report.completion_persisted);
                                assert_eq!(report.outcome.unwrap(), path);
                                let after = std::fs::metadata(&path).unwrap();
                                assert_eq!((original.dev(), original.ino()), (after.dev(), after.ino()));
                                assert_eq!(std::fs::read(&path).unwrap(), data);
                                let sequence = report.journal.get_stats().sequence;
                                let report = ScopedSparseWriter::reconcile_committed_destination(&cx, JournalCommitRecoveryRequest {
                                    journal: report.journal, transfer_id: "recover-completion".to_owned(),
                                    object_id: id, manifest, expected_chunk_commitment: pin,
                                    destination: path.clone(), max_bytes: 64, max_manifest_chunks: 64, timestamp: 4,
                                }).await.unwrap();
                                assert_eq!(report.outcome.unwrap(), path);
                                assert_eq!(report.journal.get_stats().sequence, sequence + 1,
                                    "repeated recovery supplies a fresh completion barrier, not a bare read");
                                let cfg = config(directory.path());
                                let mut owner = report.journal;
                                let summary = cx.scoped_fs().run_io(move |_| {
                                    owner.compact().unwrap();
                                    drop(owner);
                                    Ok(AppendJournal::new(cfg, AuthKey::from_seed(42)).unwrap()
                                        .get_resume_summary("recover-completion").unwrap())
                                }).await.unwrap();
                                assert_eq!(summary.status, TransferResumeStatus::Committed {
                                    final_path: path.to_str().unwrap().to_owned(), committed_size: data.len() as u64,
                                });
                            });
                            drained(&runtime);
                        }
                    }
                }
            }
        }

        #[test]
        fn completion_recovery_refuses_corruption_missing_output_and_bad_limits_without_records() {
            for case in 0..8 {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut request = published_without_completion(&cx, directory.path(), b"abcdefgh", 2,
                        CommitPolicy::CopyAndVerify).await;
                    let original_path = request.destination.clone();
                    match case {
                        0 => std::fs::write(&original_path, b"tampered").unwrap(),
                        1 => std::fs::write(&original_path, b"abc").unwrap(),
                        2 => std::fs::write(&original_path, b"abcdefgh-extra").unwrap(),
                        3 => request.destination = directory.path().join("absent"),
                        4 => request.expected_chunk_commitment = Some(ManifestChunkCommitment::new([0; 32])),
                        5 => request.max_bytes = 7,
                        6 => request.max_manifest_chunks = 2,
                        7 => request.expected_chunk_commitment = None,
                        _ => unreachable!(),
                    }
                    let bytes = std::fs::read(&original_path).unwrap();
                    let sequence = request.journal.get_stats().sequence;
                    let report = ScopedSparseWriter::reconcile_committed_destination(&cx, request).await.unwrap();
                    assert!(matches!(
                        report.outcome,
                        Outcome::Err(
                            SparseWriterError::VerificationFailed(_)
                                | SparseWriterError::FileOpen(_)
                        )
                    ));
                    assert!(!report.content_verified && !report.destination_synced && !report.completion_persisted);
                    assert_eq!(report.journal.get_stats().sequence, sequence);
                    assert_eq!(report.journal.get_resume_summary("recover-completion").unwrap().status,
                        TransferResumeStatus::CommitIntentPending);
                    assert_eq!(std::fs::read(original_path).unwrap(), bytes);
                });
                drained(&runtime);
            }
        }

        #[test]
        fn completion_recovery_cannot_mask_conflicting_terminal_history() {
            for case in 0..8 {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(1);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut request = published_without_completion(&cx, directory.path(), b"data", 0,
                        CommitPolicy::AtomicRename).await;
                    let path = request.destination.clone();
                    let mut records = match case {
                        0 => vec![JournalRecord::Cancellation {
                            transfer_id: request.transfer_id.clone(), reason: "stopped".to_owned(),
                            timestamp: 4, auth_tag: AuthenticationTag::zero(),
                        }],
                        1 => vec![JournalRecord::Rollback {
                            transfer_id: request.transfer_id.clone(), rollback_reason: "aborted".to_owned(),
                            checkpoint_sequence: 0, timestamp: 4, auth_tag: AuthenticationTag::zero(),
                        }],
                        2 => vec![JournalRecord::Offer {
                            transfer_id: request.transfer_id.clone(), object_id: request.object_id.clone(),
                            manifest_root: request.manifest.merkle_root.clone(), total_size: 5,
                            timestamp: 4, auth_tag: AuthenticationTag::zero(),
                        }],
                        3 => vec![JournalRecord::ChunkWritten {
                            transfer_id: request.transfer_id.clone(), chunk_offset: 0, chunk_size: 4,
                            file_path: "never-open-this-record-path".to_owned(), timestamp: 4,
                            auth_tag: AuthenticationTag::zero(),
                        }],
                        4..=6 => vec![JournalRecord::CommitComplete {
                            transfer_id: request.transfer_id.clone(),
                            final_path: if case == 4 { "another-destination".to_owned() }
                                else { path.to_str().unwrap().to_owned() },
                            committed_size: if case == 5 { 5 } else { 4 },
                            timestamp: 4, auth_tag: AuthenticationTag::zero(),
                        }],
                        7 => Vec::new(),
                        _ => unreachable!(),
                    };
                    if case <= 2 || case == 6 { records.push(intent(&request.manifest)); }
                    let mut owner = request.journal;
                    let cfg = config(directory.path());
                    request.journal = cx.scoped_fs().run_io(move |_| {
                        for record in records { owner.append(record).unwrap(); }
                        owner.flush().unwrap();
                        drop(owner);
                        Ok(AppendJournal::new(cfg, AuthKey::from_seed(if case == 7 { 99 } else { 42 })).unwrap())
                    }).await.unwrap();
                    let sequence = request.journal.get_stats().sequence;
                    let report = ScopedSparseWriter::reconcile_committed_destination(&cx, request).await.unwrap();
                    assert!(matches!(report.outcome, Outcome::Err(_)));
                    assert!(!report.content_verified && !report.destination_synced && !report.completion_persisted);
                    assert_eq!(report.journal.get_stats().sequence, sequence);
                    assert_eq!(std::fs::read(path).unwrap(), b"data");
                });
                drained(&runtime);
            }
        }

        #[test]
        fn completion_recovery_requires_an_offer_and_intent_before_destination_io() {
            for include_offer in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(1);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (id, manifest, pin) = expected(b"data", 0);
                    let record = if include_offer {
                        JournalRecord::Offer {
                            transfer_id: "recover-completion".to_owned(), object_id: id.clone(),
                            manifest_root: manifest.merkle_root.clone(), total_size: 4,
                            timestamp: 1, auth_tag: AuthenticationTag::zero(),
                        }
                    } else { intent(&manifest) };
                    let cfg = config(directory.path());
                    let journal = cx.scoped_fs().run_io(move |_| {
                        let mut journal = AppendJournal::new(cfg, AuthKey::from_seed(42)).unwrap();
                        journal.append(record).unwrap();
                        journal.flush().unwrap();
                        Ok(journal)
                    }).await.unwrap();
                    let path = directory.path().join("absent");
                    let report = ScopedSparseWriter::reconcile_committed_destination(&cx, JournalCommitRecoveryRequest {
                        journal, transfer_id: "recover-completion".to_owned(), object_id: id,
                        manifest, expected_chunk_commitment: pin, destination: path.clone(),
                        max_bytes: 8, max_manifest_chunks: 8, timestamp: 2,
                    }).await.unwrap();
                    assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::VerificationFailed(_))),
                        "history refusal must precede the missing file open");
                    assert_eq!(report.journal.get_stats().sequence, 1);
                    assert!(!path.exists());
                });
                drained(&runtime);
            }
        }

        #[test]
        fn completion_recovery_sync_and_terminal_failures_keep_independent_observations() {
            for terminal in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut request = published_without_completion(&cx, directory.path(), b"data", 0,
                        CommitPolicy::AtomicRename).await;
                    let path = request.destination.clone();
                    if terminal {
                        let mut cfg = config(directory.path());
                        cfg.max_journal_size = 1;
                        let owner = request.journal;
                        request.journal = cx.scoped_fs().run_io(move |_| {
                            drop(owner);
                            let journal = AppendJournal::new(cfg.clone(), AuthKey::from_seed(42)).unwrap();
                            let next = journal.get_stats().generation + 1;
                            std::fs::write(cfg.base_dir.join(format!("journal_gen_{next:06}.dat")), [1])?;
                            Ok(journal)
                        }).await.unwrap();
                    }
                    let report = ScopedSparseWriter::reconcile_destination_with(&cx, request, move |file, path| {
                        if terminal { sync_destination(file, path) }
                        else { Err(io::Error::other("injected destination barrier")) }
                    }).await.unwrap();
                    assert!(report.content_verified);
                    assert_eq!(report.destination_synced, terminal);
                    assert!(!report.completion_persisted);
                    if terminal {
                        assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::WriteFailed(_))));
                        assert!(matches!(report.journal.get_resume_summary("recover-completion"), Outcome::Err(_)));
                    } else {
                        assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::SyncFailed(ref reason))
                            if reason == "injected destination barrier"));
                        assert_eq!(report.journal.get_resume_summary("recover-completion").unwrap().status,
                            TransferResumeStatus::CommitIntentPending);
                    }
                    assert_eq!(std::fs::read(path).unwrap(), b"data");
                });
                drained(&runtime);
            }
        }

        #[test]
        fn completion_recovery_refuses_symlinks_and_observed_inode_replacement() {
            for case in 0..3 {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(1);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut request = published_without_completion(&cx, directory.path(), b"data", 0,
                        CommitPolicy::AtomicRename).await;
                    let original = request.destination.clone();
                    let backup = directory.path().join("retained-original");
                    let replacement = directory.path().join("replacement");
                    let sequence = request.journal.get_stats().sequence;
                    if case == 0 {
                        symlink(&original, &replacement).unwrap();
                        request.destination = replacement.clone();
                    } else if case == 1 {
                        std::fs::create_dir(&replacement).unwrap();
                        request.destination = replacement.clone();
                    } else {
                        std::fs::write(&replacement, b"data").unwrap();
                    }
                    let report = ScopedSparseWriter::reconcile_destination_with(&cx, request, move |file, path| {
                        sync_destination(file, path)?;
                        // Real metadata race fixture; retain, rather than delete,
                        // the verified inode. The replacement has identical bytes.
                        std::fs::rename(path, backup)?;
                        std::fs::rename(replacement, path)
                    }).await.unwrap();
                    assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                    assert_eq!(report.content_verified, case == 2);
                    assert!(!report.destination_synced && !report.completion_persisted);
                    assert_eq!(report.journal.get_stats().sequence, sequence);
                    assert_eq!(std::fs::read(original).unwrap(), b"data");
                });
                drained(&runtime);
            }
        }

        #[test]
        fn completion_recovery_dropped_wait_drains_running_work_and_reopens_its_completion() {
            for workers in [1, 2] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let request = published_without_completion(&cx, directory.path(), b"data", 0,
                        CommitPolicy::AtomicRename).await;
                    let path = request.destination.clone();
                    let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                    let (started, mut start) = oneshot::channel();
                    let (release, wait) = mpsc::channel();
                    let mut recovering = Box::pin(ScopedSparseWriter::reconcile_destination_with(
                        region.cx(), request, move |file, path| {
                            started.send_blocking(()).unwrap();
                            wait.recv_timeout(Duration::from_secs(10)).unwrap();
                            sync_destination(file, path)
                        },
                    ));
                    poll_fn(|task| { assert!(recovering.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                    start.recv(&cx).await.unwrap();
                    drop(recovering);
                    let mut closing = Box::pin(region.close());
                    poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                    release.send(()).unwrap();
                    closing.await.unwrap();
                    let cfg = config(directory.path());
                    let summary = cx.scoped_fs().run_io(move |_| {
                        Ok(AppendJournal::new(cfg, AuthKey::from_seed(42)).unwrap()
                            .get_resume_summary("recover-completion").unwrap())
                    }).await.unwrap();
                    assert_eq!(summary.status, TransferResumeStatus::Committed {
                        final_path: path.to_str().unwrap().to_owned(), committed_size: 4,
                    });
                    assert_eq!(std::fs::read(path).unwrap(), b"data");
                });
                drained(&runtime);
            }
        }

        #[test]
        fn completion_recovery_precancellation_and_changed_completed_files_do_not_write_records() {
            for cancelled in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(1);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut request = published_without_completion(&cx, directory.path(), b"data", 0,
                        CommitPolicy::AtomicRename).await;
                    let path = request.destination.clone();
                    let sequence = request.journal.get_stats().sequence;
                    if cancelled {
                        let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                        region.cx().cancel_with(CancelKind::User, Some("before completion recovery"));
                        let result = ScopedSparseWriter::reconcile_committed_destination(region.cx(), request).await;
                        assert!(matches!(result, Err(ScopedFsError::Checkpoint(_))));
                        region.close().await.unwrap();
                        let cfg = config(directory.path());
                        let reopened = cx.scoped_fs().run_io(move |_| {
                            Ok(AppendJournal::new(cfg, AuthKey::from_seed(42)).unwrap())
                        }).await.unwrap();
                        assert_eq!(reopened.get_stats().sequence, sequence);
                        assert_eq!(reopened.get_resume_summary("recover-completion").unwrap().status,
                            TransferResumeStatus::CommitIntentPending);
                    } else {
                        let owner = request.journal;
                        // A retained matching Complete must not suppress fresh
                        // verification. Use the actual recovery method once first.
                        let report = ScopedSparseWriter::reconcile_committed_destination(&cx, JournalCommitRecoveryRequest {
                            journal: owner, transfer_id: request.transfer_id.clone(),
                            object_id: request.object_id.clone(), manifest: Arc::clone(&request.manifest),
                            expected_chunk_commitment: request.expected_chunk_commitment,
                            destination: path.clone(), max_bytes: 64, max_manifest_chunks: 64, timestamp: 3,
                        }).await.unwrap();
                        report.outcome.unwrap();
                        request.journal = report.journal;
                        std::fs::write(&path, b"evil").unwrap();
                        let report = ScopedSparseWriter::reconcile_committed_destination(&cx, request).await.unwrap();
                        assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                        assert!(!report.content_verified && !report.completion_persisted);
                        assert_eq!(report.journal.get_stats().sequence, sequence + 1);
                        assert_eq!(std::fs::read(&path).unwrap(), b"evil");
                    }
                });
                drained(&runtime);
            }
        }
    }
}
