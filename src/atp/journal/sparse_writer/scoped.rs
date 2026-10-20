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
//! `ScopedSparseWriter::new` includes destination-filesystem probes in the same
//! owned blocking gateway as subsequent operations. `into_scoped` also accepts
//! a writer prepared through the historical synchronous host-boundary API.
//! Existing path-race and publication-policy limitations remain unchanged.
//!
//! A single cancel-safe admission permit is shared by every clone. Contending
//! calls wait as futures before pool submission, instead of consuming workers
//! while blocked on this writer's synchronous operation lock. The permit moves
//! into the submitted closure: dropping its wait cannot release a running job's
//! slot before its core operation returns. This serializes core execution, not
//! subsequent runtime retirement or memory held by all awaiting callers.

use super::{
    ChunkRange, Manifest, ManifestChunkCommitment, SparseWriter, SparseWriterConfig, SparseWriterError,
    SparseWriterStats, WriteOptions,
};
use crate::atp::object::ObjectId;
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::fs::scoped::ScopedFsError;
use crate::sync::semaphore::OwnedAcquireFuture;
use crate::sync::{OwnedSemaphorePermit, Semaphore};
use crate::types::Outcome;
use std::fs::File;
use std::future::{Future, poll_fn};
use std::io;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;

mod finalize;
mod receive;
mod restore;

/// Runtime admission/retirement and the writer's actual outcome are separate.
///
/// `Err` reports a `ScopedFs` authority, checkpoint, admission, or child failure.
/// `Ok(outcome)` preserves exactly what the running writer returned, including
/// a filesystem/verification error or a successful effect after cancellation.
/// Neither an outer nor an inner error is evidence that publication rolled back.
/// An unexpected internal-queue failure is `ScopedFsError::Io` with an
/// `AcquireError` source, not a filesystem operation. Context cancellation and
/// budget refusals while waiting remain `ScopedFsError::Checkpoint`.
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
    admission: Arc<Semaphore>,
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
        ScopedSparseWriter {
            writer: Arc::new(self),
            admission: Arc::new(Semaphore::new(1)),
        }
    }
}

impl ScopedSparseWriter {
    /// Construct a writer entirely on the region-owned blocking pool.
    ///
    /// Destination-filesystem probes, their temporary files, and writer state
    /// construction all happen after I/O/spawn admission. No destination or
    /// staging file is published by construction. The path manager may create
    /// its quarantine directory. Existing probe policies and best-effort
    /// probe-file cleanup remain unchanged; cancellation does not roll them back.
    ///
    /// An unpolled call has no filesystem effects. Dropping a started wait
    /// requests cancellation; its region retains the job and destroys an
    /// abandoned writer before close completes. Running OS probes cannot be
    /// preempted. A completed writer returned after cancellation is still valid
    /// and can be used with another live, authorized context.
    pub async fn new<Caps>(
        cx: &Cx<Caps>,
        object_id: ObjectId,
        final_path: PathBuf,
        config: SparseWriterConfig,
    ) -> ScopedWriterResult<Self>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        Self::create_with(cx, move || SparseWriter::new_blocking(object_id, final_path, config)).await
    }

    // Keep constructor placement, domain mapping and abandoned-result ownership
    // on the real gateway; tests may gate this exact boundary without mocking it.
    async fn create_with<Caps, F>(cx: &Cx<Caps>, create: F) -> ScopedWriterResult<Self>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce() -> Outcome<SparseWriter, SparseWriterError> + Send + 'static,
    {
        cx.scoped_fs().run_io(move |_| {
            Ok(match create() {
                Outcome::Ok(writer) => Outcome::Ok(writer.into_scoped()),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            })
        }).await
    }

    // Acquire before submitting any pool job. Observe the explicitly supplied
    // context's cancellation even when it is not the currently polling task's
    // Cx. The semaphore owns FIFO/rollback; the explicit Cx owns checkpoints.
    async fn reserve<Caps>(&self, cx: &Cx<Caps>) -> Result<OwnedSemaphorePermit, ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        if !cx.capabilities().io {
            return Err(ScopedFsError::CapabilityDenied);
        }
        cx.checkpoint().map_err(ScopedFsError::Checkpoint)?;
        let mut cancelled = pin!(cx.cancelled());
        // This is an internal execution gate, not an application obligation.
        // A child-region admission context need not be a live task holder.
        // Avoid minting a caller-held obligation before the real pool task is
        // admitted; that task, not this queue entry, owns filesystem work.
        let mut acquiring = pin!(OwnedAcquireFuture::new_uncancelable(
            Arc::clone(&self.admission), 1,
        ));
        poll_fn(|task| {
            // Register before checking so cancellation between checking and
            // queue registration cannot be lost. Checkpoint respects masking.
            let _ = cancelled.as_mut().poll(task);
            if !cx.capabilities().io {
                return std::task::Poll::Ready(Err(ScopedFsError::CapabilityDenied));
            }
            if let Err(error) = cx.checkpoint() {
                return std::task::Poll::Ready(Err(ScopedFsError::Checkpoint(error)));
            }
            acquiring.as_mut().poll(task).map(|result| {
                result.map_err(|error| ScopedFsError::Io(io::Error::other(error)))
            })
        }).await
    }

    // `ScopedFs` is the single authority/checkpoint/admission/cancel/drain
    // implementation. Wrapping the domain outcome in Ok deliberately does not
    // convert successful late effects into an artificial cancellation result.
    async fn run<Caps, F, T>(&self, cx: &Cx<Caps>, operation: F) -> ScopedWriterResult<T>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> Outcome<T, SparseWriterError> + Send + 'static,
        T: Send + 'static,
    {
        let permit = self.reserve(cx).await?;
        let writer = Arc::clone(&self.writer);
        cx.scoped_fs().run_io(move |_| {
            // Hold through the operation itself, not merely the borrowing
            // await. Refusal, queued cancellation, panic and ordinary return
            // all restore capacity using the permit's existing RAII behavior.
            let _permit = permit;
            Ok(operation(&writer))
        }).await
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

#[cfg(test)]
#[path = "scoped_construction_tests_inline_tests.rs"]
mod construction_tests;

// Journal terminal decisions compose with the existing writer lifecycle here;
// no competing cancellation executor, file owner, or cleanup path is introduced.
mod journal_cancellation {
    use super::{CapSetRuntimeMask, Cx, HasIo, HasSpawn, ScopedFsError, ScopedSparseWriter};
    use crate::atp::journal::append_journal::JournalError;
    use crate::atp::journal::sparse_writer::{
        SparseWriter, SparseWriterError, VerificationState, WriterLifecycle,
    };
    use crate::atp::journal::{
        AppendJournal, JournalCancelReport, JournalCancelRequest, JournalRecord,
        TransferResumeStatus,
    };
    use crate::atp::object::ObjectKind;
    use crate::security::AuthenticationTag;
    use crate::types::Outcome;
    use std::sync::Arc;

    macro_rules! value {
        ($outcome:expr) => {
            match $outcome {
                Outcome::Ok(value) => value,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        };
    }

    fn invalid(message: &str) -> SparseWriterError {
        SparseWriterError::VerificationFailed(message.to_owned())
    }

    fn journal_error(error: JournalError) -> SparseWriterError {
        SparseWriterError::WriteFailed(format!("cancellation journal: {error}"))
    }

    impl ScopedSparseWriter {
        /// Persist authenticated cancellation before cleaning up private staging.
        ///
        /// One FIFO permit and region-owned filesystem job cover history checks,
        /// a signed Cancellation, its sync barrier, and canonical cancel/cleanup.
        /// Only an existing matching Offer authorizes this operation. Any prior
        /// commit intent, completion or rollback refuses even if a later record
        /// calls the transfer cancelled. No journal path is opened for cleanup.
        ///
        /// A fresh cancellation record is appended and synchronized on EVERY
        /// admitted attempt, including a retry after cleanup failure or reopen.
        /// Merely reading an old record is not a new durability barrier. Repeated
        /// reasons must match; retries do not rewrite the original explanation.
        /// This barrier is required even when automatic journal sync is disabled
        /// or the writer uses FsyncPolicy::Never. Payload bytes need not be valid.
        ///
        /// Before attempting terminal persistence the writer enters its existing
        /// sealed uncertainty state and loses prior verification. Any persistence
        /// error or panic retains that state and all staging: do not retry with
        /// plain cancel/commit. Reopen and explicitly reconcile the evidence.
        /// Only a successful terminal barrier permits canonical cleanup. Cleanup
        /// failure retains durable cancellation and the existing cleanup-retry
        /// state; normal cancel can then retry cleanup without more journal I/O.
        ///
        /// Ordinary outcomes return the original journal and separate persistence
        /// and cleanup observations. Dropping a wait drains admitted work, not
        /// rollback. Use a live authorized cleanup Cx, after finishing/dropping any
        /// receive session that holds this writer's permit. Outer gateway failure
        /// or an abandoned report requires reopening storage after region drain.
        ///
        /// The application must own the journal and its trusted recovery catalog
        /// exclusively. Host path races, external mutation, directory durability
        /// outside Unix, and physical reclamation after power loss remain outside
        /// this contract. Existing cancel APIs and live sinks are not switched.
        pub async fn cancel_to_journal<Caps>(
            &self,
            cx: &Cx<Caps>,
            request: JournalCancelRequest,
        ) -> Result<JournalCancelReport, ScopedFsError>
        where
            Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        {
            self.cancel_journal_with(cx, request, persist_cancellation, SparseWriter::cancel_blocking)
                .await
        }

        // Fault seams retain the real admission, authentication, terminal fence
        // and reporting. Production always uses the canonical storage/cleanup.
        async fn cancel_journal_with<Caps, P, C>(
            &self,
            cx: &Cx<Caps>,
            mut request: JournalCancelRequest,
            persist: P,
            cleanup: C,
        ) -> Result<JournalCancelReport, ScopedFsError>
        where
            Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
            P: FnOnce(&mut AppendJournal, JournalRecord) -> Outcome<(), SparseWriterError>
                + Send + 'static,
            C: FnOnce(&SparseWriter) -> Outcome<(), SparseWriterError> + Send + 'static,
        {
            let permit = self.reserve(cx).await?;
            let writer = Arc::clone(&self.writer);
            cx.scoped_fs().run_io(move |_| {
                let _permit = permit;
                let mut cancellation_persisted = false;
                let mut cleanup_attempted = false;
                let outcome = cancel_writer(
                    &writer, &mut request, &mut cancellation_persisted,
                    &mut cleanup_attempted, persist, cleanup,
                );
                Ok(JournalCancelReport {
                    journal: request.journal, cancellation_persisted, cleanup_attempted, outcome,
                })
            }).await
        }
    }

    fn persist_cancellation(
        journal: &mut AppendJournal,
        record: JournalRecord,
    ) -> Outcome<(), SparseWriterError> {
        value!(journal.append(record).map_err(journal_error));
        journal.flush().map_err(journal_error)
    }

    fn cancel_writer<P, C>(
        writer: &SparseWriter,
        request: &mut JournalCancelRequest,
        cancellation_persisted: &mut bool,
        cleanup_attempted: &mut bool,
        persist: P,
        cleanup: C,
    ) -> Outcome<(), SparseWriterError>
    where
        P: FnOnce(&mut AppendJournal, JournalRecord) -> Outcome<(), SparseWriterError>,
        C: FnOnce(&SparseWriter) -> Outcome<(), SparseWriterError>,
    {
        let operation = writer.operation.lock();
        value!(validate_cancellation(writer, request));
        let record = JournalRecord::Cancellation {
            transfer_id: request.transfer_id.clone(), reason: request.reason.clone(),
            timestamp: request.timestamp, auth_tag: AuthenticationTag::zero(),
        };
        {
            let mut state = writer.lock_state();
            // The existing Committing state fences ALL plain writes, verify,
            // commit and cancel. This does not claim a publisher was invoked.
            // Install it before storage, including before a possible unwind.
            state.verification_state = VerificationState::Pending;
            state.lifecycle = WriterLifecycle::Committing;
        }
        value!(persist(&mut request.journal, record));
        *cancellation_persisted = true;
        writer.lock_state().lifecycle = WriterLifecycle::Cancelling;
        // The outer FIFO permit still excludes clones. Canonical cleanup takes
        // this synchronous lock itself, so do not recursively acquire it.
        drop(operation);
        *cleanup_attempted = true;
        cleanup(writer)
    }

    fn validate_cancellation(
        writer: &SparseWriter,
        request: &JournalCancelRequest,
    ) -> Outcome<(), SparseWriterError> {
        if request.transfer_id.is_empty() || request.transfer_id.len() > 4096
            || request.reason.is_empty() || request.reason.len() > 4096
        {
            return Outcome::Err(invalid("cancellation requires bounded nonempty ID and reason"));
        }
        if let Err(error) = request.manifest.validate() {
            return Outcome::Err(invalid(&format!("cancellation manifest: {error}")));
        }
        let (id, length) = {
            let state = writer.lock_state();
            if matches!(state.lifecycle, WriterLifecycle::Committed | WriterLifecycle::Committing) {
                return Outcome::Err(SparseWriterError::CommitFailed(
                    "cannot journal cancellation of a committed or unresolved writer".to_owned(),
                ));
            }
            let Some(object) = request.manifest.objects.get(&state.object_id) else {
                return Outcome::Err(invalid("cancellation manifest omits the selected file"));
            };
            let Some(length) = object.size_bytes else {
                return Outcome::Err(invalid("cancellation requires an offered file length"));
            };
            if object.id != state.object_id || object.kind != ObjectKind::FileObject
                || state.expected_size != Some(length)
            {
                return Outcome::Err(invalid("cancellation file identity or length mismatch"));
            }
            (state.object_id.clone(), length)
        };
        // The summary authenticates every indexed transfer record, and refuses
        // a journal whose preceding storage result is unresolved.
        let summary = value!(request.journal.get_resume_summary(&request.transfer_id)
            .map_err(journal_error));
        if !matches!(summary.status,
            TransferResumeStatus::Resumable | TransferResumeStatus::Cancelled { .. })
        {
            return Outcome::Err(invalid("cancellation refuses missing or terminal transfer history"));
        }
        let entries = value!(request.journal.get_transfer_entries(&request.transfer_id)
            .map_err(journal_error));
        let mut offered = false;
        let mut cancelled = false;
        for entry in entries {
            match &entry.record {
                JournalRecord::Offer { object_id, manifest_root, total_size, .. } => {
                    if cancelled || object_id != &id
                        || manifest_root != &request.manifest.merkle_root || *total_size != length
                    {
                        return Outcome::Err(invalid("cancellation conflicts with offered identity"));
                    }
                    offered = true;
                }
                JournalRecord::Cancellation { reason, .. } => {
                    if !offered || reason != &request.reason {
                        return Outcome::Err(invalid("cancellation reason or offer is inconsistent"));
                    }
                    cancelled = true;
                }
                JournalRecord::Accept { .. }
                | JournalRecord::ChunkReceived { .. }
                | JournalRecord::ChunkVerified { .. }
                | JournalRecord::ChunkWritten { .. }
                | JournalRecord::RepairDecode { .. }
                | JournalRecord::ProofDigest { .. } if offered && !cancelled => {}
                // A last-record-wins summary must not hide an earlier intent,
                // completion, rollback, or progress added after cancellation.
                _ => return Outcome::Err(invalid("cancellation history contains a conflicting transition")),
            }
        }
        if !offered {
            return Outcome::Err(invalid("cancellation requires an authenticated matching offer"));
        }
        Outcome::Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::atp::journal::{
            FsyncPolicy, JournalCheckpointRequest, JournalConfig, JournalRestoreLimits,
            SparseWriterConfig, WriteOptions,
        };
        use crate::atp::manifest::Manifest;
        use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
        use crate::channel::oneshot;
        use crate::cx::ChildRegionSpec;
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
        use crate::security::AuthKey;
        use crate::types::CancelKind;
        use std::future::{Future, poll_fn};
        use std::path::{Path, PathBuf};
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

        fn config(base: &Path) -> JournalConfig {
            JournalConfig {
                base_dir: base.join("journal"), force_sync: false,
                max_journal_size: u64::MAX, max_generations: 0,
                recent_entries_limit: 1, ..JournalConfig::default()
            }
        }

        fn open(config: JournalConfig) -> AppendJournal {
            AppendJournal::new(config, AuthKey::from_seed(42)).unwrap()
        }

        fn request(journal: AppendJournal, manifest: Arc<Manifest>) -> JournalCancelRequest {
            JournalCancelRequest {
                journal, manifest, transfer_id: "cancelled-transfer".to_owned(),
                reason: "application stopped".to_owned(), timestamp: 20,
            }
        }

        async fn prepared(
            cx: &Cx, base: &Path, bytes: &[u8], quarantine: bool, cfg: JournalConfig,
        ) -> (ScopedSparseWriter, Arc<Manifest>, AppendJournal, PathBuf) {
            let object = Object::file(bytes.to_vec());
            let id = object.id.clone();
            let mut graph = ObjectGraph::new();
            graph.add_root(object).unwrap();
            let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
            let writer = ScopedSparseWriter::new(cx, id, base.join("destination"), SparseWriterConfig {
                enable_preallocation: false, enable_quarantine: quarantine,
                fsync_policy: FsyncPolicy::Never, ..SparseWriterConfig::default()
            }).await.unwrap().unwrap();
            writer.set_expected_size(cx, bytes.len() as u64).await.unwrap().unwrap();
            if !bytes.is_empty() {
                writer.write_chunk(cx, 0, bytes.to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            }
            let report = writer.checkpoint_to_journal(cx, JournalCheckpointRequest {
                journal: open(cfg), transfer_id: "cancelled-transfer".to_owned(),
                manifest: Arc::clone(&manifest), timestamp: 10,
                limits: JournalRestoreLimits { max_bytes: 64, max_chunks: 8, max_chunk_bytes: 64 },
            }).await.unwrap();
            let path = report.outcome.unwrap().source_path;
            cx.scoped_fs().write(base.join("destination"), b"existing destination".to_vec()).await.unwrap();
            (writer, manifest, report.journal, path)
        }

        fn assert_cancelled(journal: &AppendJournal) {
            let summary = journal.get_resume_summary("cancelled-transfer").unwrap();
            assert_eq!(summary.status, TransferResumeStatus::Cancelled {
                reason: "application stopped".to_owned(),
            });
            assert!(summary.durable_chunks.is_empty());
            assert_eq!(summary.durable_bytes, 0);
        }

        #[test]
        fn cancellation_reopens_terminal_after_cleanup_and_retention() {
            for workers in [1, 2] {
                for quarantine in [false, true] {
                    for bytes in [b"".as_slice(), b"data".as_slice()] {
                        let directory = tempfile::tempdir().unwrap();
                        let runtime = runtime(workers);
                        runtime.block_on(async {
                            let cx = Cx::current().unwrap();
                            let cfg = config(directory.path());
                            let (writer, manifest, mut journal, staging) = prepared(
                                &cx, directory.path(), bytes, quarantine, cfg.clone(),
                            ).await;
                            journal.append(JournalRecord::Cancellation {
                                transfer_id: "other".to_owned(), reason: "unrelated".to_owned(),
                                timestamp: 11, auth_tag: AuthenticationTag::zero(),
                            }).unwrap();
                            let report = writer.cancel_to_journal(&cx, request(journal, manifest.clone())).await.unwrap();
                            assert!(report.cancellation_persisted);
                            assert!(report.cleanup_attempted);
                            report.outcome.unwrap();
                            assert!(!staging.exists());
                            assert_eq!(std::fs::read(directory.path().join("destination")).unwrap(), b"existing destination");
                            assert_eq!(writer.writer.lock_state().lifecycle, WriterLifecycle::Cancelled);
                            let mut journal = report.journal;
                            assert_cancelled(&journal);
                            journal.compact().unwrap();
                            drop(journal);
                            let journal = open(cfg);
                            assert_cancelled(&journal);
                            assert_eq!(journal.get_transfer_entries("other").unwrap().len(), 1);
                            let before = journal.get_stats().sequence;
                            let retry = writer.cancel_to_journal(&cx, request(journal, manifest)).await.unwrap();
                            retry.outcome.unwrap();
                            assert!(retry.cancellation_persisted && retry.cleanup_attempted);
                            assert_eq!(retry.journal.get_stats().sequence, before + 1);
                            assert_eq!(writer.admission.available_permits(), 1);
                        });
                        drained(&runtime);
                    }
                }
            }
        }

        #[test]
        fn terminal_barrier_precedes_cleanup_and_failed_cleanup_can_retry() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest, journal, staging) = prepared(
                    &cx, directory.path(), b"data", false, config(directory.path()),
                ).await;
                let saved = staging.clone();
                let cfg = config(directory.path());
                let report = writer.cancel_journal_with(&cx, request(journal, manifest.clone()),
                    move |journal, record| {
                        assert_eq!(std::fs::read(&saved).unwrap(), b"data");
                        assert_eq!(journal.get_resume_summary("cancelled-transfer").unwrap().status,
                            TransferResumeStatus::Resumable);
                        persist_cancellation(journal, record)
                    }, move |core| {
                        assert_eq!(core.lock_state().lifecycle, WriterLifecycle::Cancelling);
                        assert_cancelled(&open(cfg));
                        Outcome::Err(SparseWriterError::CommitFailed("cleanup witness".to_owned()))
                    }).await.unwrap();
                assert!(report.cancellation_persisted && report.cleanup_attempted);
                assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::CommitFailed(reason))
                    if reason == "cleanup witness"));
                assert!(staging.exists());
                let before = report.journal.get_stats().sequence;
                let retry = writer.cancel_to_journal(&cx, request(report.journal, manifest)).await.unwrap();
                retry.outcome.unwrap();
                assert_eq!(retry.journal.get_stats().sequence, before + 1);
                assert!(!staging.exists());
            });
            drained(&runtime);
        }

        #[test]
        fn uncertain_terminal_storage_never_reopens_plain_cleanup_or_publication() {
            for after_append in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (writer, manifest, journal, staging) = prepared(
                        &cx, directory.path(), b"data", false, config(directory.path()),
                    ).await;
                    writer.verify(&cx, manifest.clone()).await.unwrap().unwrap();
                    let report = writer.cancel_journal_with(&cx, request(journal, manifest),
                        move |journal, record| {
                            if after_append { journal.append(record).unwrap(); }
                            Outcome::Err(SparseWriterError::SyncFailed("terminal witness".to_owned()))
                        }, |_| panic!("uncertain storage reached cleanup")).await.unwrap();
                    assert!(!report.cancellation_persisted && !report.cleanup_attempted);
                    assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::SyncFailed(reason))
                        if reason == "terminal witness"));
                    assert_eq!(std::fs::read(&staging).unwrap(), b"data");
                    assert_eq!(writer.writer.lock_state().lifecycle, WriterLifecycle::Committing);
                    assert_eq!(writer.writer.lock_state().verification_state, VerificationState::Pending);
                    assert!(matches!(writer.cancel(&cx).await.unwrap(), Outcome::Err(SparseWriterError::CommitFailed(_))));
                    assert!(matches!(writer.commit(&cx).await.unwrap(), Outcome::Err(SparseWriterError::CommitFailed(_))));
                    assert!(matches!(writer.set_expected_size(&cx, 8).await.unwrap(), Outcome::Err(SparseWriterError::WriteFailed(_))));
                    let summary = report.journal.get_resume_summary("cancelled-transfer").unwrap();
                    assert_eq!(matches!(summary.status, TransferResumeStatus::Cancelled { .. }), after_append);
                });
                drained(&runtime);
            }
        }

        #[test]
        fn real_compaction_failure_after_cancel_append_retains_staging_and_uncertainty() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let cfg = JournalConfig { max_journal_size: 1, ..config(directory.path()) };
                let (writer, manifest, journal, staging) = prepared(
                    &cx, directory.path(), b"data", false, cfg.clone(),
                ).await;
                let collision = cfg.base_dir.join(format!("journal_gen_{:06}.dat", journal.get_stats().generation + 1));
                std::fs::create_dir(&collision).unwrap();
                let report = writer.cancel_to_journal(&cx, request(journal, manifest)).await.unwrap();
                assert!(!report.cancellation_persisted && !report.cleanup_attempted);
                assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::WriteFailed(reason))
                    if reason.starts_with("cancellation journal:")));
                assert!(report.journal.get_resume_summary("cancelled-transfer").is_err());
                assert_eq!(std::fs::read(&staging).unwrap(), b"data");
                drop(report.journal);
                std::fs::rename(collision, directory.path().join("retained-directory-evidence")).unwrap();
                assert_cancelled(&open(cfg));
                assert!(matches!(writer.cancel(&cx).await.unwrap(), Outcome::Err(SparseWriterError::CommitFailed(_))));
            });
            drained(&runtime);
        }

        #[test]
        fn mismatched_or_hidden_terminal_authority_has_no_cancellation_effect() {
            for case in 0..8 {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(1);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let cfg = config(directory.path());
                    let (writer, manifest, mut journal, staging) = prepared(
                        &cx, directory.path(), b"data", false, cfg.clone(),
                    ).await;
                    if case < 3 {
                        let record = match case {
                            0 => JournalRecord::CommitIntent {
                                transfer_id: "cancelled-transfer".to_owned(),
                                final_manifest_root: manifest.merkle_root.clone(), timestamp: 11,
                                auth_tag: AuthenticationTag::zero(),
                            },
                            1 => JournalRecord::CommitComplete {
                                transfer_id: "cancelled-transfer".to_owned(), final_path: "elsewhere".to_owned(),
                                committed_size: 4, timestamp: 11, auth_tag: AuthenticationTag::zero(),
                            },
                            _ => JournalRecord::Rollback {
                                transfer_id: "cancelled-transfer".to_owned(), rollback_reason: "old".to_owned(),
                                checkpoint_sequence: 1, timestamp: 11, auth_tag: AuthenticationTag::zero(),
                            },
                        };
                        journal.append(record).unwrap();
                        journal.append(JournalRecord::Cancellation {
                            transfer_id: "cancelled-transfer".to_owned(), reason: "application stopped".to_owned(),
                            timestamp: 12, auth_tag: AuthenticationTag::zero(),
                        }).unwrap();
                        // The shared summary now rejects the contradictory history
                        // before cancellation's own validator can interpret it.
                        assert!(matches!(journal.get_resume_summary("cancelled-transfer"),
                            Outcome::Err(JournalError::Deserialization(reason))
                                if reason == "resume cancellation conflicts with an earlier terminal decision"));
                    }
                    if case == 3 {
                        drop(journal);
                        journal = AppendJournal::new(cfg, AuthKey::from_seed(43)).unwrap();
                    }
                    if case == 7 {
                        journal.append(JournalRecord::Offer {
                            transfer_id: "cancelled-transfer".to_owned(),
                            object_id: writer.writer.lock_state().object_id.clone(),
                            manifest_root: manifest.merkle_root.clone(), total_size: 5,
                            timestamp: 12, auth_tag: AuthenticationTag::zero(),
                        }).unwrap();
                    }
                    let before = journal.get_stats().sequence;
                    let mut input = request(journal, manifest);
                    match case {
                        4 => input.transfer_id = "absent".to_owned(),
                        5 => input.reason.clear(),
                        6 => input.reason = "x".repeat(4097),
                        _ => {}
                    }
                    let report = writer.cancel_to_journal(&cx, input).await.unwrap();
                    if case < 4 || case == 7 {
                        let expected = match case {
                            0..=2 => "cancellation journal: Deserialization failed: resume cancellation conflicts with an earlier terminal decision",
                            3 => "cancellation journal: Deserialization failed: resume journal record authentication failed",
                            7 => "cancellation journal: Deserialization failed: resume offer total_size conflict",
                            _ => unreachable!(),
                        };
                        assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::WriteFailed(reason))
                            if reason == expected));
                    } else {
                        assert!(matches!(report.outcome, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                    }
                    assert!(!report.cancellation_persisted && !report.cleanup_attempted);
                    assert_eq!(report.journal.get_stats().sequence, before);
                    assert_eq!(std::fs::read(staging).unwrap(), b"data");
                    assert_eq!(writer.writer.lock_state().lifecycle, WriterLifecycle::Accepting);
                });
                drained(&runtime);
            }
        }

        #[test]
        fn dropped_wait_keeps_the_terminal_job_and_exclusion_until_drain() {
            for workers in [1, 2] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let cfg = config(directory.path());
                    let (writer, manifest, journal, staging) = prepared(
                        &cx, directory.path(), b"data", false, cfg.clone(),
                    ).await;
                    let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                    let (started, mut start) = oneshot::channel();
                    let (release, wait) = mpsc::channel();
                    let mut cancelling = Box::pin(writer.cancel_journal_with(region.cx(), request(journal, manifest),
                        move |journal, record| {
                            started.send_blocking(()).unwrap();
                            wait.recv_timeout(Duration::from_secs(10)).unwrap();
                            persist_cancellation(journal, record)
                        }, SparseWriter::cancel_blocking));
                    let mut starting = Box::pin(start.recv(&cx));
                    poll_fn(|task| {
                        assert!(cancelling.as_mut().poll(task).is_pending());
                        starting.as_mut().poll(task)
                    }).await.unwrap();
                    drop(starting);
                    assert_eq!(writer.admission.available_permits(), 0);
                    assert!(staging.exists());
                    let mut competing = Box::pin(writer.set_expected_size(&cx, 8));
                    poll_fn(|task| {
                        assert!(competing.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    drop(cancelling);
                    assert_eq!(writer.admission.available_permits(), 0);
                    release.send(()).unwrap();
                    region.close().await.unwrap();
                    assert!(matches!(competing.await.unwrap(), Outcome::Err(SparseWriterError::WriteFailed(_))));
                    assert!(!staging.exists());
                    assert_cancelled(&open(cfg));
                    assert_eq!(writer.admission.available_permits(), 1);
                });
                drained(&runtime);
            }
        }

        #[test]
        fn persistence_panic_keeps_staging_and_releases_admission_without_cleanup() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest, journal, staging) = prepared(
                    &cx, directory.path(), b"data", false, config(directory.path()),
                ).await;
                let result = writer.cancel_journal_with(&cx, request(journal, manifest),
                    |_, _| panic!("terminal persistence witness"),
                    |_| panic!("panic reached cleanup")).await;
                assert!(matches!(result, Err(ScopedFsError::Join(_))));
                assert_eq!(writer.writer.lock_state().lifecycle, WriterLifecycle::Committing);
                assert_eq!(std::fs::read(staging).unwrap(), b"data");
                assert_eq!(writer.admission.available_permits(), 1);
            });
            drained(&runtime);
        }

        #[test]
        fn cancelled_context_refuses_but_corrupt_payload_can_be_explicitly_discarded() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let cfg = config(directory.path());
                let (writer, manifest, journal, staging) = prepared(
                    &cx, directory.path(), b"data", false, cfg.clone(),
                ).await;
                let before = journal.get_stats().sequence;
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                region.cx().cancel_with(CancelKind::User, Some("before terminal admission"));
                let refused = writer.cancel_to_journal(region.cx(), request(journal, manifest.clone())).await;
                assert!(matches!(refused, Err(ScopedFsError::Checkpoint(_))));
                region.close().await.unwrap();
                let journal = open(cfg);
                assert_eq!(journal.get_stats().sequence, before);
                cx.scoped_fs().write(staging.clone(), b"bad".to_vec()).await.unwrap();
                // Cancellation authorizes disposal, not successful content verification.
                let report = writer.cancel_to_journal(&cx, request(journal, manifest)).await.unwrap();
                report.outcome.unwrap();
                assert!(report.cancellation_persisted && report.cleanup_attempted);
                assert_cancelled(&report.journal);
                assert!(!staging.exists());
            });
            drained(&runtime);
        }
    }
}
