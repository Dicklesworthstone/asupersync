//! Exact-length stream ingestion using the existing chunk reader and file owner.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::atp::journal::{ScopedReceive, ScopedReceiveError, ScopedReceiveOptions, ScopedReceiveResult};
use crate::atp::journal::{
    FsyncPolicy, JournalCommitRequest, JournalPublication, JournalReceiveReport,
    JournalReceiveRequest, ScopedJournalReceive,
};
use crate::atp::journal::receive::{JournalCheckpointSlot, ReceiveStartGate};
use crate::io::{AsyncRead, AsyncReadExt};
use crate::net::atp::chunk::profiles::ChunkingProfile as _;
use crate::net::atp::chunk::reader::StreamChunkReader;
use crate::net::atp::chunk::stream::StreamProfile;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

#[path = "receive_resume.rs"]
mod resume;

#[path = "receive_integrity.rs"]
mod integrity;
use integrity::ReceiveIntegrity;

struct ReceiveRequest {
    manifest: Arc<Manifest>,
    options: ScopedReceiveOptions,
    expected: Option<ManifestChunkCommitment>,
    resume_offset: Option<u64>,
}

#[derive(Default)]
struct ReceivePersistence {
    journal: Option<ReceiveJournal>,
    publication: Option<JournalPublication>,
}

struct ReceiveJournal {
    request: JournalCommitRequest,
    checkpoint_bytes: u64,
    saved_offset: u64,
    observation: JournalCheckpointSlot,
    start: Arc<ReceiveStartGate>,
}

impl ReceiveJournal {
    fn validate_policy(
        &self,
        writer: &SparseWriter,
        options: ScopedReceiveOptions,
        start: Option<u64>,
    ) -> Result<(), SparseWriterError> {
        let state = writer.lock_state();
        SparseWriter::require_accepting(&state)?;
        let invalid = |message: &str| SparseWriterError::VerificationFailed(message.to_owned());
        if writer.config.fsync_policy == FsyncPolicy::Never || state.final_path.to_str().is_none() {
            return Err(invalid("journaled receive requires durability and a UTF-8 destination"));
        }
        let object = self.request.checkpoint.manifest.objects.get(&state.object_id)
            .ok_or_else(|| invalid("journaled receive object is absent"))?;
        let length = object.size_bytes
            .ok_or_else(|| invalid("journaled receive needs a declared object length"))?;
        let remaining = length.checked_sub(start.unwrap_or(0))
            .ok_or_else(|| invalid("journaled receive offset exceeds object length"))?;
        if remaining.min(options.chunk_size as u64)
            > self.request.checkpoint.limits.max_chunk_bytes as u64
        {
            return Err(invalid("receive chunks exceed the restoration buffer limit"));
        }
        Ok(())
    }

    fn checkpoint(&mut self, writer: &SparseWriter) -> Outcome<(), SparseWriterError> {
        super::restore::checkpoint_receive(writer, &mut self.request.checkpoint).map(|saved| {
            self.saved_offset = saved.summary.contiguous_prefix_bytes;
            let saved = Arc::new(saved);
            let retired = self.observation.lock().replace(saved);
            drop(retired);
        })
    }
}

impl ScopedSparseWriter {
    /// Receive with automatic checkpoints and durable journaled publication.
    ///
    /// One writer admission slot spans preflight, the initial checkpoint,
    /// source ingestion, periodic checkpoints, fresh verification and journaled
    /// publication. Existing receive APIs remain unjournaled. The returned
    /// session's `prepare_checkpoint` exposes an optional catalog-persistence
    /// boundary before source reads or publication, including for empty objects.
    pub fn receive_to_journal<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        request: JournalReceiveRequest,
    ) -> io::Result<ScopedJournalReceive<R>>
    where
        R: AsyncRead + Unpin + Send + 'static,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        let JournalReceiveRequest { commit, mut options, checkpoint_bytes, resume_offset } = request;
        if options.chunk_size == 0 || options.chunk_size as u64 > StreamProfile::max_chunk_size()
            || checkpoint_bytes == 0 || commit.checkpoint.limits.max_chunk_bytes == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journaled receive requires valid chunk and nonzero checkpoint limits",
            ));
        }
        options.max_bytes = options.max_bytes.min(commit.checkpoint.limits.max_bytes);
        options.max_chunks = options.max_chunks.min(commit.checkpoint.limits.max_chunks);
        let writer = self.clone();
        let cx = cx.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let progress = Arc::clone(&accepted);
        let checkpoint = Arc::new(parking_lot::Mutex::new(None));
        let observation = Arc::clone(&checkpoint);
        let start = Arc::new(ReceiveStartGate::default());
        let body_start = Arc::clone(&start);
        let work = Box::pin(async move {
            let mut source = source;
            let request = ReceiveRequest {
                manifest: Arc::clone(&commit.checkpoint.manifest),
                options,
                expected: commit.expected_chunk_commitment,
                resume_offset,
            };
            let mut persistence = ReceivePersistence {
                journal: Some(ReceiveJournal {
                    request: commit,
                    checkpoint_bytes,
                    saved_offset: 0,
                    observation,
                    start: body_start,
                }),
                publication: Some(JournalPublication::NotAttempted),
            };
            let outcome = writer
                .receive_body(&cx, &mut source, request, progress, &mut persistence)
                .await;
            let source = if matches!(&outcome, Ok(Outcome::Ok(_))) {
                Some(source)
            } else {
                None
            };
            let report = JournalReceiveReport {
                journal: persistence
                    .journal
                    .map(|owned| owned.request.checkpoint.journal),
                publication: persistence.publication,
                outcome,
            };
            (source, report)
        });
        Ok(ScopedJournalReceive {
            work: Some(work),
            source: None,
            accepted,
            checkpoint,
            start,
            poisoned: false,
        })
    }

    /// Receive exactly the selected manifest object's bytes and publish them.
    ///
    /// The writer must be fresh (no staging inode or prior chunks), the selected
    /// file object must declare its size, and the manifest must be trusted. Whole-file
    /// hashes and content-addressed IDs are checked by the canonical verifier.
    /// Chunk-only manifest-addressed objects require the pinned variant below.
    ///
    /// One payload chunk is read, written and drained before the next source
    /// poll. Source fragmentation does not change ledger entries. The source's
    /// own buffering, the supplied manifest and existing writer metadata are
    /// separate memory costs; `max_chunks` bounds new ledger entries, not those
    /// caller-provided allocations. The source need not close at the body end.
    /// Completed manifest chunks are checked before their completing batch is
    /// written. Earlier fragments may already be staged; final on-disk content
    /// verification remains mandatory. Resumption reconstructs crossing hashes
    /// from the retained prefix before polling the replacement source.
    ///
    /// Construction is lazy and returns `InvalidInput` for an invalid chunk size
    /// without polling the source. The session retains its context. A terminal
    /// cancellation/error is terminal for this session. Explicit suffix recovery
    /// uses `checked_receive_offset` and `resume_exact_at` on the retained writer;
    /// it never repolls the failed session or silently reconnects its source.
    pub fn receive_exact<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
    ) -> io::Result<ScopedReceive<R>>
    where
        R: AsyncRead + Unpin + Send + 'static,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.receive_session(cx, source, manifest, options, None, None)
    }

    /// Receive and publish using an independently authenticated chunk commitment.
    ///
    /// The pin and byte/chunk limits are checked before reading or creating a
    /// staging file. They are not computed from untrusted received metadata.
    /// The same canonical identity, coverage and content checks run again before
    /// publication. No transport or CLI automatically negotiates this pin.
    pub fn receive_exact_with_chunk_commitment<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
        expected: ManifestChunkCommitment,
    ) -> io::Result<ScopedReceive<R>>
    where
        R: AsyncRead + Unpin + Send + 'static,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.receive_session(cx, source, manifest, options, Some(expected), None)
    }

    fn receive_session<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
        expected: Option<ManifestChunkCommitment>,
        resume_offset: Option<u64>,
    ) -> io::Result<ScopedReceive<R>>
    where
        R: AsyncRead + Unpin + Send + 'static,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        if options.chunk_size == 0 || options.chunk_size as u64 > StreamProfile::max_chunk_size() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid receive chunk size"));
        }
        let writer = self.clone();
        let cx = cx.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let progress = Arc::clone(&accepted);
        let work = Box::pin(async move {
            let mut source = source;
            let request = ReceiveRequest { manifest, options, expected, resume_offset };
            let mut persistence = ReceivePersistence::default();
            let outcome = writer
                .receive_body(&cx, &mut source, request, progress, &mut persistence)
                .await?;
            Ok(match outcome {
                Outcome::Ok(path) => Outcome::Ok((source, path)),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            })
        });
        Ok(ScopedReceive { work: Some(work), source: None, accepted, poisoned: false })
    }

    // Pass the unique admission permit into each real pool job, then return it
    // alongside the outcome. There is never a window where a caller's dropped
    // future frees capacity while its filesystem operation is still executing.
    async fn receive_step<Caps, F, T>(
        &self,
        cx: &Cx<Caps>,
        permit: OwnedSemaphorePermit,
        operation: F,
    ) -> Result<(OwnedSemaphorePermit, T), ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> T + Send + 'static,
        T: Send + 'static,
    {
        let writer = Arc::clone(&self.writer);
        cx.scoped_fs().run_io(move |_| {
            let outcome = operation(&writer);
            Ok((permit, outcome))
        }).await
    }

    // A domain error still returns journal ownership. A gateway failure instead
    // drops its captured owner: callers must reopen retained storage rather than
    // fabricate a usable journal after uncertain effects.
    async fn receive_persistent_step<Caps, F, T>(
        &self,
        cx: &Cx<Caps>,
        permit: OwnedSemaphorePermit,
        persistence: &mut ReceivePersistence,
        operation: F,
    ) -> Result<(OwnedSemaphorePermit, T), ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter, &mut Option<ReceiveJournal>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let mut owned = persistence.journal.take();
        let (permit, (returned, result)) = self
            .receive_step(cx, permit, move |writer| {
                let result = operation(writer, &mut owned);
                (owned, result)
            })
            .await?;
        persistence.journal = returned;
        Ok((permit, result))
    }

    async fn receive_body<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &mut R,
        request: ReceiveRequest,
        accepted: Arc<AtomicU64>,
        persistence: &mut ReceivePersistence,
    ) -> ScopedReceiveResult<PathBuf>
    where
        R: AsyncRead + Unpin + Send,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        let ReceiveRequest { manifest, options, expected, resume_offset } = request;
        let permit = self.reserve(cx).await?;
        let (mut permit, preflight) = self
            .receive_persistent_step(cx, permit, persistence, move |writer, journal| {
                if let Some(journal) = journal {
                    if let Err(error) = journal.validate_policy(writer, options, resume_offset) {
                        use crate::atp::journal::sparse_writer::{
                            VerificationState, WriterLifecycle,
                        };
                        let mut state = writer.lock_state();
                        if state.lifecycle == WriterLifecycle::Accepting {
                            state.verification_state =
                                VerificationState::Failed { reason: error.to_string() };
                        }
                        return Outcome::Err(error);
                    }
                }
                integrity::prepare_integrity(
                    writer,
                    manifest,
                    options,
                    expected.as_ref(),
                    resume_offset,
                )
                .and_then(|integrity| match journal {
                    Some(journal) => journal.checkpoint(writer).map(|()| integrity),
                    None => Outcome::Ok(integrity),
                })
            })
            .await?;
        let mut integrity = match preflight {
            Outcome::Ok(integrity) => integrity,
            Outcome::Err(error) => return Ok(Outcome::Err(error)),
            Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
            Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
        };
        let length = integrity.length;
        let mut offset = resume_offset.unwrap_or(0);
        accepted.store(offset, Ordering::Relaxed);
        if let Some(journal) = persistence.journal.as_ref() {
            let start = Arc::clone(&journal.start);
            // Preparation holds this future, not a pool worker. Only a later
            // session wait opens the latch and immediately repolls it. Place
            // this BEFORE even the empty-object finalization path.
            poll_fn(|_| start.poll_admit()).await;
        }
        let limited = source.take(length - offset);
        let mut chunks = StreamChunkReader::new(limited, options.chunk_size)
            .map_err(ScopedReceiveError::Source)?;
        while offset < length {
            let mut reading = pin!(chunks.next_chunk_with_cx(cx));
            let chunk = poll_fn(|task| {
                if !cx.capabilities().io {
                    return Poll::Ready(Err(ScopedReceiveError::Gateway(ScopedFsError::CapabilityDenied)));
                }
                reading.as_mut().poll(task).map(|result| result.map_err(ScopedReceiveError::Source))
            }).await?;
            let Some(chunk) = chunk else {
                return Err(ScopedReceiveError::Source(io::Error::new(
                    io::ErrorKind::UnexpectedEof, "source ended before the declared object length",
                )));
            };
            let size = chunk.bytes.len() as u64;
            let progress = Arc::clone(&accepted);
            let (returned, written) = self
                .receive_persistent_step(cx, permit, persistence, move |writer, journal| {
                    if let Err(reason) = integrity.check_chunk(&chunk) {
                        return writer.fail_verification(reason).map(|()| integrity);
                    }
                    writer
                        .write_chunk_blocking(offset, &chunk.bytes, WriteOptions::default())
                        .and_then(|_| {
                            if let Some(journal) = journal {
                                let end = offset + size;
                                progress.store(end, Ordering::Relaxed);
                                if end == length
                                    || end.saturating_sub(journal.saved_offset)
                                        >= journal.checkpoint_bytes
                                {
                                    return journal.checkpoint(writer).map(|()| integrity);
                                }
                            }
                            Outcome::Ok(integrity)
                        })
                })
                .await?;
            permit = returned;
            match written {
                Outcome::Ok(checked) => {
                    integrity = checked;
                    offset += size; // Take and the canonical chunk reader bound this by length.
                    accepted.store(offset, Ordering::Relaxed);
                }
                Outcome::Err(error) => return Ok(Outcome::Err(error)),
                Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
                Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
            }
        }
        // No EOF probe: following protocol bytes stay in the source. The same
        // admission permit covers ingress, fresh verification and publication.
        let journaled = persistence.journal.is_some();
        if journaled {
            persistence.publication = None;
        }
        let (_permit, (result, publication)) = self
            .receive_persistent_step(cx, permit, persistence, move |writer, journal| {
                let mut publication =
                    journaled.then_some(JournalPublication::NotAttempted);
                if let Some(journal) = journal {
                    let result = match integrity.finish() {
                        Ok(()) => super::restore::finalize_receive(
                            writer,
                            &mut journal.request,
                            publication
                                .as_mut()
                                .expect("journaled publication observation"),
                        ),
                        Err(reason) => {
                            writer.fail_verification(reason).map(|()| PathBuf::new())
                        }
                    };
                    return (result, publication);
                }
                let verification = match integrity.finish() {
                    Ok(()) => writer.verify_inner(&integrity.manifest, expected.as_ref()),
                    Err(reason) => writer.fail_verification(reason),
                };
                let result = match verification {
                    Outcome::Ok(()) => writer.commit_with_fsync(File::sync_all),
                    Outcome::Err(error) => Outcome::Err(error),
                    Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => Outcome::Panicked(payload),
                };
                (result, publication)
            })
            .await?;
        persistence.publication = publication;
        Ok(result)
    }
}

fn prepare_receive(
    writer: &SparseWriter,
    manifest: &Manifest,
    options: ScopedReceiveOptions,
    expected: Option<&ManifestChunkCommitment>,
    resume_offset: Option<u64>,
) -> Outcome<u64, SparseWriterError> {
    let prepare = || -> Result<u64, SparseWriterError> {
        let invalid = |message: String| SparseWriterError::VerificationFailed(message);
        if let Some(expected) = expected {
            expected.verify(manifest).map_err(|error| invalid(error.to_string()))?;
        } else {
            manifest.validate().map_err(|error| invalid(error.to_string()))?;
        }
        let length = {
            let state = writer.lock_state();
            SparseWriter::require_accepting(&state)?;
            if resume_offset.is_none()
                && (state.temp_file.is_some() || state.temp_path.is_some() || !state.written_chunks.is_empty())
            {
                return Err(SparseWriterError::WriteFailed("receive requires a fresh writer".to_owned()));
            }
            let object = manifest.objects.get(&state.object_id)
                .ok_or_else(|| invalid("selected receive object is missing".to_owned()))?;
            if object.id != state.object_id {
                return Err(invalid("receive object identity mismatch".to_owned()));
            }
            if object.kind != crate::atp::object::ObjectKind::FileObject {
                return Err(invalid("receive requires a file object".to_owned()));
            }
            let size = object.size_bytes.ok_or_else(|| invalid("receive object size is required".to_owned()))?;
            let start = resume_offset.unwrap_or(0);
            if start > size || (resume_offset.is_some() && state.expected_size != Some(size)) {
                return Err(invalid("receive resume size or offset mismatch".to_owned()));
            }
            let existing_chunks = u64::try_from(state.written_chunks.len())
                .map_err(|_| invalid("receive chunk count overflow".to_owned()))?;
            let new_chunks = (size - start).div_ceil(options.chunk_size as u64);
            if size > options.max_bytes || existing_chunks.checked_add(new_chunks)
                .is_none_or(|count| count > u64::from(options.max_chunks))
            {
                return Err(invalid("receive object exceeds byte or chunk limit".to_owned()));
            }
            // Final verification checks even optional hints. Reject impossible
            // ranges and bad empty digests before any body or staging effects.
            ReceiveIntegrity::validate_ranges(&object.chunk_boundaries, size).map_err(invalid)?;
            if object.content_hash.is_none() && !object.id.is_content_addressed() {
                if expected.is_none() {
                    return Err(invalid("chunk-only receive requires a trusted commitment".to_owned()));
                }
                SparseWriter::require_complete_manifest_chunks(&object.chunk_boundaries, size)
                    .map_err(invalid)?;
            }
            size
        };
        if let Some(offset) = resume_offset {
            // The same admission slot remains held from this revalidation until
            // the suffix and final publication settle. A previously observed
            // offset is not a reservation and must never authorize skipping data.
            if resume::checked_prefix(writer)? != offset {
                return Err(invalid("receive resume offset differs from recorded prefix".to_owned()));
            }
            // Even a full prefix must pass this session's final verification.
            // Cancellation before that job cannot leave an earlier manifest's
            // successful evidence available for a separate plain commit.
            writer.lock_state().verification_state =
                crate::atp::journal::sparse_writer::VerificationState::Pending;
        }
        writer.set_expected_size(length)?;
        Ok(length)
    };
    match prepare() {
        Ok(length) => Outcome::Ok(length),
        Err(error) => {
            // A failed resumed expectation must not leave an older successful
            // verification available to a later plain commit. Sealed terminal
            // evidence is not rewritten by a refused attempt to reuse it.
            if resume_offset.is_some() {
                use crate::atp::journal::sparse_writer::{VerificationState, WriterLifecycle};
                let mut state = writer.lock_state();
                if state.lifecycle == WriterLifecycle::Accepting {
                    state.verification_state = VerificationState::Failed { reason: error.to_string() };
                }
            }
            Outcome::Err(error)
        }
    }
}

#[cfg(test)]
#[path = "receive_tests.rs"]
mod tests;

#[cfg(test)]
mod journaled_tests {
    use super::*;
    use crate::atp::journal::{
        AppendJournal, CommitPolicy, JournalCheckpointRequest, JournalConfig,
        JournalRecord, JournalRestoreLimits, JournalRestoreRequest, TransferResumeStatus,
    };
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::io::ReadBuf;
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use crate::security::{AuthKey, AuthenticationTag};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Waker};
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

    fn journal_config(base: &std::path::Path) -> JournalConfig {
        JournalConfig {
            base_dir: base.join("journal"), force_sync: false,
            max_journal_size: u64::MAX, max_generations: 0,
            recent_entries_limit: 1, ..JournalConfig::default()
        }
    }

    fn reopen(base: &std::path::Path) -> AppendJournal {
        AppendJournal::new(journal_config(base), AuthKey::from_seed(42)).unwrap()
    }

    fn request(journal: AppendJournal, manifest: Arc<Manifest>, interval: u64) -> JournalReceiveRequest {
        JournalReceiveRequest {
            commit: JournalCommitRequest {
                checkpoint: JournalCheckpointRequest {
                    journal, transfer_id: "automatic".to_owned(), manifest,
                    limits: JournalRestoreLimits { max_bytes: 64, max_chunks: 32, max_chunk_bytes: 4 },
                    timestamp: 31,
                },
                expected_chunk_commitment: None,
            },
            options: ScopedReceiveOptions { max_bytes: 64, max_chunks: 32, chunk_size: 2 },
            checkpoint_bytes: interval,
            resume_offset: None,
        }
    }

    async fn prepared(
        cx: &Cx, base: &std::path::Path, data: &[u8], policy: CommitPolicy,
    ) -> (ScopedSparseWriter, Arc<Manifest>) {
        let object = Object::file(data.to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
        let writer = ScopedSparseWriter::new(cx, id, base.join("destination"), SparseWriterConfig {
            enable_preallocation: false, fsync_policy: FsyncPolicy::BeforeCommit,
            commit_policy: policy, ..SparseWriterConfig::default()
        }).await.unwrap().unwrap();
        (writer, manifest)
    }

    #[derive(Default)]
    struct Probe {
        consumed: AtomicUsize,
        polls: AtomicUsize,
        parked: AtomicBool,
        released: AtomicBool,
        waker: parking_lot::Mutex<Option<Waker>>,
    }

    struct Source {
        bytes: Vec<u8>, position: usize, fragment: usize,
        pause_at: Option<usize>, fail_at: Option<usize>, probe: Arc<Probe>,
    }

    impl Source {
        fn new(bytes: &[u8]) -> (Self, Arc<Probe>) {
            let probe = Arc::new(Probe::default());
            (Self {
                bytes: bytes.to_vec(), position: 0, fragment: 1,
                pause_at: None, fail_at: None, probe: Arc::clone(&probe),
            }, probe)
        }
    }

    impl AsyncRead for Source {
        fn poll_read(
            self: Pin<&mut Self>, task: &mut Context<'_>, buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.probe.polls.fetch_add(1, Ordering::SeqCst);
            if this.pause_at.is_some_and(|at| this.position >= at) {
                let retired = this.probe.waker.lock().replace(task.waker().clone());
                drop(retired);
                this.probe.parked.store(true, Ordering::SeqCst);
                if !this.probe.released.load(Ordering::SeqCst) { return Poll::Pending; }
            }
            if this.fail_at.is_some_and(|at| this.position >= at) {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            let mut count = this.fragment.min(buffer.remaining()).min(this.bytes.len() - this.position);
            if let Some(at) = this.pause_at.filter(|_| !this.probe.released.load(Ordering::SeqCst)) {
                count = count.min(at.saturating_sub(this.position));
            }
            if let Some(at) = this.fail_at { count = count.min(at.saturating_sub(this.position)); }
            buffer.put_slice(&this.bytes[this.position..this.position + count]);
            this.position += count;
            this.probe.consumed.store(this.position, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    fn release(probe: &Probe) {
        probe.released.store(true, Ordering::SeqCst);
        let wake = probe.waker.lock().take();
        if let Some(wake) = wake { wake.wake(); }
    }

    async fn park(cx: &Cx, receive: &mut ScopedJournalReceive<Source>, probe: &Probe) {
        let mut wait = Box::pin(receive.wait());
        crate::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
            assert!(wait.as_mut().poll(task).is_pending(), "receive ended before source witness");
            if probe.parked.load(Ordering::SeqCst) { Poll::Ready(()) } else { Poll::Pending }
        })).await.expect("source did not reach its parked boundary");
        // This borrowing wait is intentionally dropped; the session keeps work.
    }

    #[test]
    fn journaled_receive_publishes_and_reopens_without_consuming_following_protocol_bytes() {
        for workers in [1, 2] {
            for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                for data in [b"".as_slice(), b"abcdefgh".as_slice()] {
                    for interval in [1, 5, u64::MAX] {
                        let directory = tempfile::tempdir().unwrap();
                        let runtime = runtime(workers);
                        runtime.block_on(async {
                            let cx = Cx::current().unwrap();
                            let (writer, manifest) = prepared(&cx, directory.path(), data, policy).await;
                            let mut body = data.to_vec();
                            body.extend_from_slice(b"NEXT");
                            let (source, probe) = Source::new(&body);
                            let mut request = request(reopen(directory.path()), manifest, interval);
                            request.commit.expected_chunk_commitment = Some(
                                ManifestChunkCommitment::from_manifest(&request.commit.checkpoint.manifest).unwrap(),
                            );
                            let mut receiving = writer.receive_to_journal(&cx, source, request).unwrap();
                            assert!(receiving.last_checkpoint().is_none());
                            let report = receiving.wait().await.unwrap();
                            let path = directory.path().join("destination");
                            assert_eq!(report.outcome.unwrap().unwrap(), path);
                            assert_eq!(report.publication, Some(JournalPublication::Confirmed(path.clone())));
                            assert_eq!(probe.consumed.load(Ordering::SeqCst), data.len());
                            assert_eq!(receiving.accepted_bytes(), data.len() as u64);
                            assert_eq!(receiving.last_checkpoint().unwrap().summary.contiguous_prefix_bytes, data.len() as u64);
                            let mut source = receiving.take_source().unwrap();
                            let mut following = [0; 4];
                            source.read_exact(&mut following).await.unwrap();
                            assert_eq!(&following, b"NEXT");
                            assert!(receiving.take_source().is_none());
                            assert!(matches!(receiving.wait().await, Err(ScopedReceiveError::Completed)));
                            assert_eq!(std::fs::read(&path).unwrap(), data);
                            let mut journal = report.journal.unwrap();
                            let entries = journal.get_transfer_entries("automatic").unwrap();
                            assert_eq!(entries.len(), 3 * data.len().div_ceil(2) + 3);
                            assert!(matches!(entries[entries.len() - 2].record, JournalRecord::CommitIntent { .. }));
                            assert!(matches!(entries.last().unwrap().record, JournalRecord::CommitComplete { .. }));
                            journal.compact().unwrap();
                            drop(journal);
                            assert_eq!(reopen(directory.path()).get_resume_summary("automatic").unwrap().status,
                                TransferResumeStatus::Committed {
                                    final_path: path.to_str().unwrap().to_owned(), committed_size: data.len() as u64,
                                });
                            assert_eq!(writer.admission.available_permits(), 1);
                        });
                        drained(&runtime);
                    }
                }
            }
        }
    }

    #[test]
    fn failed_source_returns_the_journal_and_durable_prefix_restores_into_suffix_receive() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::CopyAndVerify).await;
                let (mut source, probe) = Source::new(b"abcdefghNEXT");
                source.fail_at = Some(4);
                let mut receiving = writer.receive_to_journal(&cx, source,
                    request(reopen(directory.path()), manifest.clone(), 4)).unwrap();
                let report = receiving.wait().await.unwrap();
                assert!(matches!(report.outcome, Err(ScopedReceiveError::Source(error))
                    if error.kind() == io::ErrorKind::ConnectionReset));
                assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
                assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
                assert_eq!(receiving.accepted_bytes(), 4);
                assert!(receiving.take_source().is_none());
                let saved = receiving.last_checkpoint().unwrap();
                assert_eq!(saved.summary.contiguous_prefix_bytes, 4);
                let journal = report.journal.unwrap();
                assert_eq!(journal.get_resume_summary("automatic").unwrap().durable_bytes, 4);
                drop(journal);
                drop(writer);
                let restored = ScopedSparseWriter::restore_from_storage(&cx, JournalRestoreRequest {
                    journal_config: journal_config(directory.path()), auth_key: AuthKey::from_seed(42),
                    transfer_id: "automatic".to_owned(), source_path: saved.source_path.clone(),
                    final_path: directory.path().join("restored"),
                    writer_config: SparseWriterConfig { enable_preallocation: false, ..SparseWriterConfig::default() },
                    limits: JournalRestoreLimits { max_bytes: 64, max_chunks: 32, max_chunk_bytes: 4 },
                }).await.unwrap().unwrap();
                let mut request = request(reopen(directory.path()), manifest, 3);
                request.resume_offset = Some(4);
                let mut resumed = restored.receive_to_journal(&cx, b"efghNEXT".as_slice(), request).unwrap();
                let report = resumed.wait().await.unwrap();
                assert_eq!(report.outcome.unwrap().unwrap(), directory.path().join("restored"));
                assert_eq!(resumed.take_source().unwrap(), b"NEXT");
                assert_eq!(std::fs::read(directory.path().join("restored")).unwrap(), b"abcdefgh");
                assert_eq!(std::fs::read(&saved.source_path).unwrap(), b"abcd");
                assert_ne!(resumed.last_checkpoint().unwrap().source_path, saved.source_path);
                assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 15);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn checkpoint_failure_keeps_actual_written_bytes_but_stops_the_next_source_poll() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
            let mut config = journal_config(directory.path());
            config.max_journal_size = 1;
            let journal = AppendJournal::new(config.clone(), AuthKey::from_seed(42)).unwrap();
            let (mut source, probe) = Source::new(b"abcdefgh");
            source.fragment = 2;
            source.pause_at = Some(0);
            let mut receiving = writer.receive_to_journal(&cx, source, request(journal, manifest, 2)).unwrap();
            park(&cx, &mut receiving, &probe).await;
            assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 0);
            assert!(config.base_dir.join("journal_gen_000001.dat").is_file());
            // Initial Offer rotated to generation 1. A real conflicting frontier
            // makes automatic rotation after the next append fail and fence it.
            cx.scoped_fs().write(config.base_dir.join("journal_gen_000002.dat"), vec![]).await.unwrap();
            release(&probe);
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::WriteFailed(message)))
                if message.contains("frontier")));
            assert_eq!(receiving.accepted_bytes(), 2);
            assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 2);
            assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 0);
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 2);
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            let journal = report.journal.unwrap();
            assert!(journal.get_resume_summary("automatic").is_err());
            drop(journal);
            let reopened = AppendJournal::new(config, AuthKey::from_seed(42)).unwrap();
            assert_eq!(reopened.get_resume_summary("automatic").unwrap().durable_bytes, 0);
            assert!(!directory.path().join("destination").exists());
            assert_eq!(writer.admission.available_permits(), 1);
        });
        drained(&runtime);
    }

    #[test]
    fn dropped_borrowing_wait_retains_the_checkpoint_and_excludes_competing_writer_clones() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
                let (mut source, probe) = Source::new(b"abcdefghNEXT");
                source.pause_at = Some(4);
                let mut receiving = writer.receive_to_journal(&cx, source,
                    request(reopen(directory.path()), manifest, 2)).unwrap();
                park(&cx, &mut receiving, &probe).await;
                let snapshot = receiving.last_checkpoint().unwrap();
                assert_eq!(snapshot.summary.contiguous_prefix_bytes, 4);
                assert_eq!(receiving.accepted_bytes(), 4);
                assert!(!directory.path().join("destination").exists());
                let clone = writer.clone();
                let mut resizing = Box::pin(clone.set_expected_size(&cx, 9));
                poll_fn(|task| { assert!(resizing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                assert_eq!(writer.admission.telemetry_snapshot(0).waiter_count, 1);
                drop(resizing);
                assert_eq!(writer.admission.telemetry_snapshot(0).waiter_count, 0);
                release(&probe);
                let report = receiving.wait().await.unwrap();
                assert_eq!(report.outcome.unwrap().unwrap(), directory.path().join("destination"));
                assert_eq!(receiving.accepted_bytes(), 8);
                assert_eq!(receiving.last_checkpoint().unwrap().summary.contiguous_prefix_bytes, 8);
                assert_eq!(snapshot.summary.contiguous_prefix_bytes, 4, "snapshots are immutable observations");
                assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 15);
                assert_eq!(probe.consumed.load(Ordering::SeqCst), 8);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn invalid_history_pin_and_limits_refuse_before_source_or_staging() {
        for case in 0..7 {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
                let mut request = request(reopen(directory.path()), manifest, 2);
                match case {
                    0 => request.commit.checkpoint.limits.max_bytes = 7,
                    1 => request.commit.checkpoint.limits.max_chunks = 3,
                    2 => request.commit.checkpoint.limits.max_chunk_bytes = 1,
                    3 => request.commit.expected_chunk_commitment = Some(ManifestChunkCommitment::new([0; 32])),
                    4 => { request.commit.checkpoint.journal.append(JournalRecord::Cancellation {
                        transfer_id: "automatic".to_owned(), reason: "stop".to_owned(), timestamp: 1,
                        auth_tag: AuthenticationTag::zero(),
                    }).unwrap(); }
                    5 => request.resume_offset = Some(9),
                    6 => request.commit.checkpoint.transfer_id.clear(),
                    _ => unreachable!(),
                }
                let sequence = request.commit.checkpoint.journal.get_stats().sequence;
                let (source, probe) = Source::new(b"abcdefgh");
                let mut receiving = writer.receive_to_journal(&cx, source, request).unwrap();
                let report = receiving.wait().await.unwrap();
                assert!(matches!(report.outcome, Ok(Outcome::Err(_))));
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                assert_eq!(report.journal.unwrap().get_stats().sequence, sequence);
                assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
                assert!(receiving.last_checkpoint().is_none());
                assert!(writer.writer.lock_state().temp_file.is_none());
                assert!(!directory.path().join("destination").exists());
            });
            drained(&runtime);
        }
    }

    #[test]
    fn incremental_corruption_has_no_payload_checkpoint_or_publication() {
        use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
        use sha2::{Digest, Sha256};
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, mut manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
            let expected = Arc::make_mut(&mut manifest);
            expected.objects.values_mut().next().unwrap().chunk_boundaries = vec![ChunkBoundary {
                index: 0, byte_offset: 0, size_bytes: 2,
                content_hash: Sha256::digest(b"ab").into(), strategy: ChunkStrategy::FixedSize, metadata: None,
            }];
            expected.merkle_root = MerkleRoot::from_manifest_components(
                &expected.objects, &expected.chunk_plan, &expected.raptorq_layout,
                &expected.compression_policy, &expected.encryption_policy, &expected.capability_policy,
                &expected.transform_order, &expected.transform_proof_policy, &expected.repair_groups,
            );
            let (source, probe) = Source::new(b"XXcdefgh");
            let mut receiving = writer.receive_to_journal(&cx, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::VerificationFailed(message)))
                if message.contains("hash mismatch")));
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 2);
            assert_eq!(receiving.accepted_bytes(), 0);
            assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 0);
            assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 1);
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            assert!(!directory.path().join("destination").exists());
        });
        drained(&runtime);
    }

    #[test]
    fn cancelled_and_unpolled_sessions_do_not_start_a_checkpoint() {
        fn assert_send<T: Send>(_: &T) {}
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
            let unpolled = writer.receive_to_journal(&cx, b"data".as_slice(),
                request(reopen(directory.path()), manifest.clone(), 2)).unwrap();
            assert_send(&unpolled);
            drop(unpolled);
            assert!(writer.writer.lock_state().temp_file.is_none());
            let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            child.cancel_with(crate::types::CancelKind::User, Some("before journal receive"));
            let (source, probe) = Source::new(b"data");
            let mut receiving = writer.receive_to_journal(child, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Err(ScopedReceiveError::Gateway(ScopedFsError::Checkpoint(_)))));
            assert_eq!(report.journal.unwrap().get_stats().sequence, 0);
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert!(receiving.last_checkpoint().is_none());
            assert!(writer.writer.lock_state().temp_file.is_none());
            assert_eq!(writer.admission.available_permits(), 1);
            region.close().await.unwrap();
        });
        drained(&runtime);
    }

    #[test]
    fn truncated_source_distinguishes_written_tail_from_the_last_durable_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
            let mut receiving = writer.receive_to_journal(&cx, b"abc".as_slice(),
                request(reopen(directory.path()), manifest, 2)).unwrap();
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Err(ScopedReceiveError::Source(error))
                if error.kind() == io::ErrorKind::UnexpectedEof));
            assert_eq!(receiving.accepted_bytes(), 3);
            let saved = receiving.last_checkpoint().unwrap();
            assert_eq!(saved.summary.contiguous_prefix_bytes, 2);
            assert_eq!(report.journal.unwrap().get_resume_summary("automatic").unwrap().durable_bytes, 2);
            assert_eq!(std::fs::read(&saved.source_path).unwrap(), b"abc");
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            assert!(receiving.take_source().is_none());
            assert!(!directory.path().join("destination").exists());
        });
        drained(&runtime);
    }

    #[test]
    fn failed_final_publication_retains_the_intent_and_never_returns_the_source() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = directory.path().join("destination");
                // A directory is a deterministic rename refusal, even as root.
                cx.scoped_fs().create_dir_all(path.clone()).await.unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
                let mut receiving = writer.receive_to_journal(&cx, b"dataNEXT".as_slice(),
                    request(reopen(directory.path()), manifest, u64::MAX)).unwrap();
                let report = receiving.wait().await.unwrap();
                assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::CommitFailed(_)))));
                assert_eq!(report.publication, Some(JournalPublication::Unconfirmed));
                let journal = report.journal.unwrap();
                assert_eq!(journal.get_resume_summary("automatic").unwrap().status,
                    TransferResumeStatus::CommitIntentPending);
                assert!(!journal.get_transfer_entries("automatic").unwrap().iter()
                    .any(|entry| matches!(entry.record, JournalRecord::CommitComplete { .. })));
                assert_eq!(writer.writer.lock_state().lifecycle,
                    crate::atp::journal::sparse_writer::WriterLifecycle::Committing);
                assert!(writer.cancel(&cx).await.unwrap().is_err());
                assert!(receiving.take_source().is_none());
                assert_eq!(receiving.accepted_bytes(), 4);
                assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 4);
                assert!(path.is_dir());
                assert_eq!(writer.admission.available_permits(), 1);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn cancellation_at_a_witnessed_parked_source_retains_the_checkpoint_and_journal() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
                let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
                let child = region.cx();
                let (mut source, probe) = Source::new(b"abcdefgh");
                source.pause_at = Some(4);
                let mut receiving = writer.receive_to_journal(child, source,
                    request(reopen(directory.path()), manifest, 2)).unwrap();
                park(&cx, &mut receiving, &probe).await;
                assert_eq!(receiving.last_checkpoint().unwrap().summary.contiguous_prefix_bytes, 4);
                child.cancel_with(crate::types::CancelKind::User, Some("parked journal source"));
                let report = receiving.wait().await.unwrap();
                assert!(matches!(report.outcome, Err(ScopedReceiveError::Source(error))
                    if error.kind() == io::ErrorKind::Interrupted));
                assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
                let summary = report.journal.unwrap().get_resume_summary("automatic").unwrap();
                assert_eq!(summary.status, TransferResumeStatus::Resumable);
                assert_eq!(summary.contiguous_prefix_bytes, 4);
                assert_eq!(receiving.accepted_bytes(), 4);
                assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
                assert_eq!(writer.admission.available_permits(), 1);
                assert!(!directory.path().join("destination").exists());
                region.close().await.unwrap();
            });
            drained(&runtime);
        }
    }

    fn prepared_snapshot(result: crate::atp::journal::JournalReceivePreparation)
        -> Arc<crate::atp::journal::JournalCheckpoint>
    {
        match result {
            crate::atp::journal::JournalReceivePreparation::Checkpoint(saved) => saved,
            crate::atp::journal::JournalReceivePreparation::Stopped(_) => {
                panic!("preparation stopped before its checkpoint")
            }
        }
    }

    struct CatalogSource {
        inner: Source,
        catalog_ready: Arc<AtomicBool>,
    }

    impl AsyncRead for CatalogSource {
        fn poll_read(
            mut self: Pin<&mut Self>, task: &mut Context<'_>, buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            assert!(self.catalog_ready.load(Ordering::SeqCst),
                "source polled before the application confirmed catalog persistence");
            Pin::new(&mut self.inner).poll_read(task, buffer)
        }
    }

    #[test]
    fn prepared_receive_waits_for_catalog_before_body_and_empty_publication() {
        for workers in [1, 2] {
            for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                for content in [b"".as_slice(), b"abcdefgh".as_slice()] {
                    let directory = tempfile::tempdir().unwrap();
                    // A preparation pause must never occupy even the only pool worker.
                    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                        else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
                    let runtime = builder.blocking_threads(1, 1).build().unwrap();
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let (writer, manifest) = prepared(&cx, directory.path(), content, policy).await;
                        let mut body = content.to_vec();
                        body.extend_from_slice(b"NEXT");
                        let (source, probe) = Source::new(&body);
                        let catalog_ready = Arc::new(AtomicBool::new(false));
                        let source = CatalogSource { inner: source, catalog_ready: catalog_ready.clone() };
                        let mut receive = writer.receive_to_journal(&cx, source,
                            request(reopen(directory.path()), manifest, 2)).unwrap();
                        let saved = prepared_snapshot(receive.prepare_checkpoint().await.unwrap());
                        assert!(saved.source_path.is_file());
                        assert_eq!(saved.summary.durable_bytes, 0);
                        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                        assert_eq!(writer.admission.available_permits(), 0);
                        assert!(!directory.path().join("destination").exists());
                        assert_eq!(receive.accepted_bytes(), 0);
                        assert!(receive.take_source().is_none());
                        let again = prepared_snapshot(receive.prepare_checkpoint().await.unwrap());
                        assert!(Arc::ptr_eq(&saved, &again));
                        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                        // Constructing a wait is lazy and does not open the latch.
                        drop(receive.wait());
                        assert!(Arc::ptr_eq(&saved,
                            &prepared_snapshot(receive.prepare_checkpoint().await.unwrap())));
                        let catalog = directory.path().join("recovery-catalog");
                        let source_path = saved.source_path.clone();
                        let written_catalog = catalog.clone();
                        cx.scoped_fs().run_io(move |_| {
                            use std::io::Write;
                            let mut file = std::fs::OpenOptions::new()
                                .create_new(true).write(true).open(&written_catalog)?;
                            file.write_all(source_path.to_str().unwrap().as_bytes())?;
                            file.sync_all()?;
                            #[cfg(unix)]
                            File::open(written_catalog.parent().unwrap())?.sync_all()?;
                            Ok(())
                        }).await.unwrap();
                        assert_eq!(std::fs::read_to_string(catalog).unwrap(), saved.source_path.to_str().unwrap());
                        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                        catalog_ready.store(true, Ordering::SeqCst);
                        let report = receive.wait().await.unwrap();
                        let path = directory.path().join("destination");
                        assert_eq!(report.outcome.unwrap().unwrap(), path);
                        assert_eq!(report.publication, Some(JournalPublication::Confirmed(path.clone())));
                        assert_eq!(std::fs::read(path).unwrap(), content);
                        assert_eq!(probe.consumed.load(Ordering::SeqCst), content.len());
                        let source = receive.take_source().unwrap();
                        assert_eq!(&source.inner.bytes[source.inner.position..], b"NEXT");
                        assert!(matches!(report.journal.unwrap().get_resume_summary("automatic").unwrap().status,
                            TransferResumeStatus::Committed { .. }));
                        assert_eq!(writer.admission.available_permits(), 1);
                    });
                    drained(&runtime);
                }
            }
        }
    }

    #[test]
    fn prepared_resume_exposes_the_checked_prefix_without_reading_suffix() {
        for workers in [1, 2] {
            for prefix in [4, 8] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
                    writer.set_expected_size(&cx, 8).await.unwrap().unwrap();
                    for (index, part) in b"abcdefgh"[..prefix].chunks(4).enumerate() {
                        writer.write_chunk(&cx, (index * 4) as u64, part.to_vec(), WriteOptions::default())
                            .await.unwrap().unwrap();
                    }
                    let mut body = b"abcdefgh"[prefix..].to_vec();
                    body.extend_from_slice(b"NEXT");
                    let (source, probe) = Source::new(&body);
                    let mut input = request(reopen(directory.path()), manifest, 2);
                    input.resume_offset = Some(prefix as u64);
                    let mut receive = writer.receive_to_journal(&cx, source, input).unwrap();
                    let saved = prepared_snapshot(receive.prepare_checkpoint().await.unwrap());
                    assert_eq!(saved.summary.contiguous_prefix_bytes, prefix as u64);
                    assert_eq!(receive.accepted_bytes(), prefix as u64,
                        "preparation returned before the driver observed preflight retirement");
                    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                    assert!(!directory.path().join("destination").exists());
                    assert!(matches!(writer.writer.lock_state().verification_state,
                        crate::atp::journal::sparse_writer::VerificationState::Pending));
                    let report = receive.wait().await.unwrap();
                    assert_eq!(report.outcome.unwrap().unwrap(), directory.path().join("destination"));
                    assert_eq!(probe.consumed.load(Ordering::SeqCst), 8 - prefix);
                    assert_eq!(std::fs::read(directory.path().join("destination")).unwrap(), b"abcdefgh");
                });
                drained(&runtime);
            }
        }
    }

    #[test]
    fn preparation_failure_returns_the_original_terminal_report_once() {
        for case in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
                let mut input = request(reopen(directory.path()), manifest, 2);
                match case {
                    0 => input.commit.expected_chunk_commitment = Some(ManifestChunkCommitment::new([0; 32])),
                    1 => input.commit.checkpoint.limits.max_bytes = 3,
                    2 => { input.commit.checkpoint.journal.append(JournalRecord::Cancellation {
                        transfer_id: "automatic".to_owned(), reason: "stop".to_owned(), timestamp: 1,
                        auth_tag: AuthenticationTag::zero(),
                    }).unwrap(); }
                    _ => unreachable!(),
                }
                let sequence = input.commit.checkpoint.journal.get_stats().sequence;
                let (source, probe) = Source::new(b"dataNEXT");
                let mut receive = writer.receive_to_journal(&cx, source, input).unwrap();
                let crate::atp::journal::JournalReceivePreparation::Stopped(report) =
                    receive.prepare_checkpoint().await.unwrap()
                else { panic!("invalid preparation produced a checkpoint"); };
                assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
                assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
                assert_eq!(report.journal.unwrap().get_stats().sequence, sequence);
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                assert!(receive.last_checkpoint().is_none());
                assert!(writer.writer.lock_state().temp_file.is_none());
                assert!(matches!(receive.prepare_checkpoint().await, Err(ScopedReceiveError::Completed)));
                assert!(matches!(receive.wait().await, Err(ScopedReceiveError::Completed)));
                assert_eq!(writer.admission.available_permits(), 1);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn dropped_preparation_wait_keeps_checkpoint_job_and_body_pause() {
        use crate::channel::oneshot;
        use std::sync::mpsc;
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
            let runtime = builder.blocking_threads(1, 1).build().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
                let (source, probe) = Source::new(b"dataNEXT");
                let mut receive = writer.receive_to_journal(&cx, source,
                    request(reopen(directory.path()), manifest, 2)).unwrap();
                let (started, mut start) = oneshot::channel();
                let (release, wait) = mpsc::channel();
                let fs = cx.scoped_fs();
                let mut blocker = Box::pin(fs.run_io(move |_| {
                    started.send_blocking(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(10)).unwrap();
                    Ok(())
                }));
                poll_fn(|task| { assert!(blocker.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                start.recv(&cx).await.unwrap();
                let mut preparing = Box::pin(receive.prepare_checkpoint());
                poll_fn(|task| { assert!(preparing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                drop(preparing);
                assert_eq!(writer.admission.available_permits(), 0);
                assert!(receive.last_checkpoint().is_none());
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                release.send(()).unwrap();
                blocker.await.unwrap();
                let saved = prepared_snapshot(receive.prepare_checkpoint().await.unwrap());
                assert_eq!(saved.summary.durable_bytes, 0);
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                assert_eq!(writer.admission.available_permits(), 0);
                let report = receive.wait().await.unwrap();
                assert_eq!(report.outcome.unwrap().unwrap(), directory.path().join("destination"));
                assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 9);
                assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn preparation_after_body_admission_refuses_without_repolling_or_stopping_receive() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
            let (mut source, probe) = Source::new(b"dataNEXT");
            source.pause_at = Some(0);
            let mut receive = writer.receive_to_journal(&cx, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            park(&cx, &mut receive, &probe).await;
            let polls = probe.polls.load(Ordering::SeqCst);
            assert!(matches!(receive.prepare_checkpoint().await, Err(ScopedReceiveError::PreparationTooLate)));
            assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
            assert_eq!(writer.admission.available_permits(), 0);
            release(&probe);
            assert_eq!(receive.wait().await.unwrap().outcome.unwrap().unwrap(), directory.path().join("destination"));
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
            assert_eq!(writer.admission.available_permits(), 1);
        });
        drained(&runtime);
    }

    #[test]
    fn failed_catalog_can_abandon_preparation_without_consuming_source() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
            let (source, probe) = Source::new(b"dataNEXT");
            let mut receive = writer.receive_to_journal(&cx, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            let saved = prepared_snapshot(receive.prepare_checkpoint().await.unwrap());
            let catalog = directory.path().join("catalog");
            cx.scoped_fs().write(catalog.clone(), b"existing catalog".to_vec()).await.unwrap();
            // A real filesystem refusal, not a sleep or successful mock barrier.
            assert!(cx.scoped_fs().run_io(move |_| {
                std::fs::OpenOptions::new().create_new(true).write(true).open(catalog)?;
                Ok(())
            }).await.is_err());
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            drop(receive);
            assert_eq!(writer.admission.available_permits(), 1);
            assert!(saved.source_path.is_file());
            assert!(!directory.path().join("destination").exists());
            let summary = reopen(directory.path()).get_resume_summary("automatic").unwrap();
            assert_eq!(summary.status, TransferResumeStatus::Resumable);
            assert_eq!(summary.durable_bytes, 0);
            assert_eq!(summary.total_size, Some(4));
        });
        drained(&runtime);
    }

    #[test]
    fn precancelled_preparation_is_send_and_returns_journal_without_storage_effects() {
        fn assert_send<T: Send>(_: &T) {}
        use crate::cx::ChildRegionSpec;
        use crate::types::CancelKind;
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            child.cancel_with(CancelKind::User, Some("before preparation"));
            let (source, probe) = Source::new(b"dataNEXT");
            let mut receive = writer.receive_to_journal(child, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            let preparing = receive.prepare_checkpoint();
            assert_send(&preparing);
            drop(preparing);
            let crate::atp::journal::JournalReceivePreparation::Stopped(report) =
                receive.prepare_checkpoint().await.unwrap()
            else { panic!("pre-cancelled preparation reached checkpoint"); };
            assert!(matches!(report.outcome, Err(ScopedReceiveError::Gateway(ScopedFsError::Checkpoint(_)))));
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            assert_eq!(report.journal.unwrap().get_stats().sequence, 0);
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert!(writer.writer.lock_state().temp_file.is_none());
            assert_eq!(std::fs::read_dir(journal_config(directory.path()).base_dir).unwrap().count(), 0);
            region.close().await.unwrap();
        });
        drained(&runtime);
    }
}
