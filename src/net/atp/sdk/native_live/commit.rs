//! Application commit barriers after whole-stream verification and before Proof.
//!
//! Epoch flushes still acknowledge a prefix only. Opt-in committing receivers
//! additionally finish the sink's transaction before sending the final Proof.
//! A cancelled/timed-out commit is drained once it has started: cancellation
//! cannot roll back a filesystem publication or abandon its resource ownership.
//! This drain may outlive the operation timeout. A sink that never completes
//! cannot be safely preempted. Hard-dropping the entire receive still provides
//! no terminal report; use a scope-owned task and join it.

use super::{
    LiveStreamError, LiveStreamListener, LiveStreamReceipt, LiveStreamReport, LiveStreamTask,
    Progress, authorize, bounded,
};
use crate::cx::{Cx, Scope};
use crate::io::AsyncWrite;
use crate::types::Policy;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A sink with a separate application publication/transaction boundary.
///
/// The receiver calls this only after checking ObjectComplete, the complete
/// chain/hash/length, and the final flush. Pending calls receive the same receipt;
/// there is no automatic retry after Ready. Returning Ok asserts only the
/// implementation's documented commit contract, not universal crash durability.
/// An Err can still follow externally visible effects and MUST NOT imply rollback.
///
/// Once polled, completion must remain driveable after cooperative Cx
/// cancellation. Keep in-flight state in the sink, register a completion waker,
/// and do not require fresh cancelled-context authority to finish admitted work.
/// The owner drains this operation on timeout/cancellation before releasing its
/// sink or admission credit. Implementations must bound their own commit work.
pub trait LiveStreamCommitSink: AsyncWrite {
    /// Finish publication for exactly this verified stream, not an epoch prefix.
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>>;
}

/// Independent application-commit and transport outcomes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LiveStreamCommitError {
    /// The sink returned an error. Its external effects may be partial or final;
    /// reconcile with the sink rather than automatically retransmitting.
    #[error("live sink did not confirm application commit")]
    Unconfirmed {
        /// Validated whole-stream metadata, NOT an application commit receipt.
        receipt: Box<LiveStreamReceipt>,
        /// A timeout/cancellation observed before draining the commit, if any.
        interruption: Option<Box<LiveStreamError>>,
        /// Actual terminal sink failure, retained independently of interruption.
        #[source]
        source: io::Error,
    },
    /// The sink confirmed commit, but cancellation, timeout or transport failure
    /// prevented final Proof completion. Do not duplicate the committed effects.
    #[error("live sink committed but final peer proof did not complete")]
    CommittedWithoutProof {
        /// Metadata of the stream the sink actually acknowledged as committed.
        receipt: Box<LiveStreamReceipt>,
        /// Original interruption or Proof transmission failure.
        #[source]
        source: Box<LiveStreamError>,
    },
}

pub(super) fn proof_failed(
    receipt: &LiveStreamReceipt,
    source: LiveStreamError,
) -> LiveStreamError {
    LiveStreamError::Commit(Box::new(LiveStreamCommitError::CommittedWithoutProof {
        receipt: Box::new(receipt.clone()),
        source: Box::new(source),
    }))
}

struct Commit<'a, W> {
    sink: &'a mut W,
    receipt: &'a LiveStreamReceipt,
    started: bool,
}

impl<W: LiveStreamCommitSink + Unpin> Future for Commit<'_, W> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.started = true;
        Pin::new(&mut *this.sink).poll_commit(cx, this.receipt)
    }
}

pub(super) async fn finish<W: LiveStreamCommitSink + Unpin>(
    cx: &Cx,
    timeout: Duration,
    sink: &mut W,
    receipt: &LiveStreamReceipt,
) -> Result<(), LiveStreamError> {
    let mut commit = std::pin::pin!(Commit {
        sink,
        receipt,
        started: false
    });
    let observed = bounded(cx, timeout, "sink commit", commit.as_mut()).await;
    let (result, interruption) = match observed {
        Ok(()) => return Ok(()),
        Err(LiveStreamError::Io(source)) => (Err(source), None),
        Err(error) => {
            if !commit.as_ref().get_ref().started {
                // Never start a transaction merely to drain a cancelled wait.
                return Err(error);
            }
            // Only bounded() supplies this interruption. Do not poll an already
            // Ready sink again, restart its transaction, or detach its work.
            (commit.as_mut().await, Some(error))
        }
    };
    match result {
        Ok(()) => Err(proof_failed(
            receipt,
            interruption.expect("interrupted commit"),
        )),
        Err(source) => Err(LiveStreamError::Commit(Box::new(
            LiveStreamCommitError::Unconfirmed {
                receipt: Box::new(receipt.clone()),
                interruption: interruption.map(Box::new),
                source,
            },
        ))),
    }
}

// Preserve existing APIs' exact flush-only contract without specialization or
// a blanket implementation that would prevent a caller's own commit method.
pub(super) struct FlushOnly<W>(pub(super) W);

impl<W: AsyncWrite + Unpin> AsyncWrite for FlushOnly<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin> LiveStreamCommitSink for FlushOnly<W> {
    fn poll_commit(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        // The compatibility path passes require_commit=false and never calls us.
        Poll::Ready(Ok(()))
    }
}

impl LiveStreamListener {
    /// Receive and commit verified content before transmitting final Proof.
    ///
    /// Unlike receive_into, this explicitly opts into the sink's commit contract.
    /// Epoch acknowledgements remain prefix flushes; no wire format changes.
    /// Inspect LiveStreamError::Commit on failure: a committed sink must not be
    /// retried simply because the peer did not receive its Proof. A started
    /// commit is drained even after cancellation/timeout; see LiveStreamCommitSink.
    pub async fn receive_committing<W: LiveStreamCommitSink + Unpin>(
        self,
        cx: &Cx,
        sink: &mut W,
    ) -> LiveStreamReport {
        let mut progress = Progress::default();
        let outcome = async {
            authorize(cx)?;
            let timeout = self.receiver.config.operation_timeout;
            let (tcp, _) = bounded(cx, timeout, "accept", self.listener.accept()).await?;
            let tls = bounded(
                cx,
                timeout,
                "TLS handshake",
                self.receiver.acceptor.accept(tcp),
            )
            .await?;
            self.receiver
                .receive_authenticated_with_commit(cx, tls, sink, &mut progress, true)
                .await
        }
        .await;
        progress.report(outcome)
    }

    /// Move the bound listener, committing sink and credit into a scoped child.
    ///
    /// Join the real child to observe its drained commit and transfer outcome.
    /// Pre-start cancellation never invokes the sink's commit method.
    pub fn spawn_receive_committing<P, W>(
        self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        mut sink: W,
    ) -> Result<LiveStreamTask, LiveStreamError>
    where
        P: Policy,
        W: LiveStreamCommitSink + Unpin + Send + 'static,
    {
        authorize(cx)?;
        cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = LiveStreamReport> + Send>> =
                Box::pin(async move { self.receive_committing(&child, &mut sink).await });
            future
        })
        .map_err(LiveStreamError::Spawn)
    }
}

/// Explicit no-overwrite publication in a caller-owned private Unix directory.
#[cfg(unix)]
#[path = "commit/file.rs"]
pub mod file;

/// Authenticated connection recovery with retained source and committing sink state.
#[path = "resume.rs"]
pub mod resume;

/// Manifest-authorized publication through the canonical ATP sparse writer.
pub use manifest_sink::{ManifestFileSink, ManifestFileSinkConfig};

// Keep the transport adapter beside its existing trait, not in a second writer,
// verifier, or filesystem subsystem. All actual disk work uses ScopedSparseWriter.
mod manifest_sink {
    use super::{LiveStreamCommitSink, LiveStreamReceipt};
    use super::super::MAX_LIVE_EPOCH_BYTES;
    use crate::atp::journal::sparse_writer::{ScopedSparseWriter, ScopedWriterResult, SparseWriterError};
    use crate::atp::journal::{SparseWriterConfig, WriteOptions};
    use crate::atp::manifest::{ChunkBoundary, Manifest};
    use crate::atp::manifest_chunk_commitment::ManifestChunkCommitment;
    use crate::atp::object::{ObjectId, ObjectKind};
    use crate::cx::Cx;
    use crate::io::AsyncWrite;
    use crate::types::Outcome;
    use sha2::{Digest, Sha256};
    use std::fmt;
    use std::future::Future;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    /// Explicit local authority and bounds for one known file received live.
    ///
    /// The manifest and optional chunk commitment must come from a trusted
    /// application channel, not be accepted merely because the peer supplied them.
    /// The existing live protocol does not transport or authenticate this manifest.
    #[derive(Debug, Clone)]
    pub struct ManifestFileSinkConfig {
        /// Locally selected file identity; the peer cannot redirect this selection.
        pub object_id: ObjectId,
        /// Immutable trusted expected object graph.
        pub manifest: Arc<Manifest>,
        /// Required for a manifest-addressed file with only chunk hashes.
        pub expected_chunk_commitment: Option<ManifestChunkCommitment>,
        /// Locally selected final path. Publication uses the supplied writer policy.
        pub destination: PathBuf,
        /// Existing preallocation, fsync, cleanup and publication policies.
        /// Rename/copy policies may replace an existing destination; this is NOT
        /// the separate LiveFileSink's no-overwrite policy.
        pub writer: SparseWriterConfig,
        /// Maximum admitted manifest file length, checked before construction.
        pub max_bytes: u64,
        /// Maximum successful write receipts retained by the sparse writer.
        /// Each partial poll_write counts once; zero admits only an empty file.
        pub max_chunks: u32,
    }

    type Work = Pin<Box<dyn Future<Output = io::Result<Completion>> + Send>>;

    enum Completion {
        Written { count: usize, digest: [u8; 32], next_hash: Sha256 },
        Flushed(u64),
        Committed(PathBuf),
    }

    #[derive(Clone, Copy)]
    struct WriteReceipt {
        count: usize,
        digest: [u8; 32],
    }

    // Only the descriptor cursor and one crossing hash survive a batch. The
    // immutable manifest remains the sole owner of the descriptor table.
    #[derive(Default)]
    struct ChunkChecks {
        next: usize,
        partial: Option<Sha256>,
    }

    impl ChunkChecks {
        fn accept(
            &mut self,
            boundaries: &[ChunkBoundary],
            offset: u64,
            bytes: &[u8],
            digest: [u8; 32],
        ) -> io::Result<()> {
            let end = offset.checked_add(bytes.len() as u64)
                .ok_or_else(|| integrity_error("manifest sink chunk offset overflows".to_owned()))?;
            while let Some(boundary) = boundaries.get(self.next) {
                if boundary.byte_offset > end { break; }
                if boundary.size_bytes == 0 {
                    // Construction already checked the range and empty digest.
                    self.next += 1;
                    continue;
                }
                if boundary.byte_offset == end { break; }
                let boundary_end = boundary.byte_offset.checked_add(boundary.size_bytes)
                    .ok_or_else(|| integrity_error("manifest chunk range overflows".to_owned()))?;
                let from = offset.max(boundary.byte_offset);
                let to = end.min(boundary_end);
                if from >= to {
                    return Err(integrity_error("manifest sink skipped a chunk range".to_owned()));
                }
                let actual = if boundary.byte_offset == offset && boundary_end == end
                    && self.partial.is_none()
                {
                    // This digest was computed locally for exactly this batch.
                    digest
                } else {
                    self.partial.get_or_insert_with(Sha256::new)
                        .update(&bytes[(from - offset) as usize..(to - offset) as usize]);
                    if to < boundary_end { break; }
                    self.partial.take().expect("partial chunk was hashed").finalize().into()
                };
                if actual != boundary.content_hash {
                    return Err(integrity_error(format!("manifest chunk {} hash mismatch", boundary.index)));
                }
                self.next += 1;
            }
            Ok(())
        }

        fn finish(&mut self, boundaries: &[ChunkBoundary], offset: u64) -> io::Result<()> {
            while let Some(boundary) = boundaries.get(self.next) {
                if boundary.size_bytes != 0 || boundary.byte_offset > offset { break; }
                self.next += 1;
            }
            if self.next != boundaries.len() || self.partial.is_some() {
                return Err(integrity_error("manifest sink ended before chunk verification".to_owned()));
            }
            Ok(())
        }
    }

    fn integrity_error(reason: String) -> io::Error {
        io::Error::other(SparseWriterError::VerificationFailed(reason))
    }

    #[derive(Clone, Debug)]
    struct Failure(Arc<io::Error>);

    impl fmt::Display for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self.0.as_ref(), f)
        }
    }

    impl std::error::Error for Failure {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    impl Failure {
        fn repeat(&self) -> io::Error {
            io::Error::new(self.0.kind(), self.clone())
        }
    }

    /// Bounded AsyncWrite/LiveStreamCommitSink adapter over ScopedSparseWriter.
    ///
    /// Pass this to the existing committing live listener.
    /// Writes use at most one 64 KiB owned buffer/job; flush synchronizes the
    /// staging inode but never publishes. Commit checks the live receipt's length
    /// and raw stream hash, then invokes fresh canonical manifest verification
    /// and publication. A valid peer stream alone cannot authorize different data.
    /// Completed manifest chunks are checked before their completing write is
    /// submitted. A mismatch permanently refuses this sink; earlier fragments
    /// may already be staged. Optional hints authenticate only their own ranges:
    /// final on-disk and whole-object authentication remain mandatory.
    ///
    /// Ingress hashing runs on the polling thread over a batch of at most 64 KiB,
    /// as did the local write digest. One crossing hash survives in the sink,
    /// without copying the manifest's table or submitting another blocking job.
    /// Descriptor traversal additionally scales with the supplied manifest.
    ///
    /// New trait operations capture the CURRENT polling task's Cx, not the
    /// constructor's context. A sink prepared before spawn therefore admits disk
    /// work into the receiver child's region. Re-polls drive the retained future
    /// without requesting new authority, including after late cancellation.
    /// Polling outside a current native context refuses; no inline fallback exists.
    ///
    /// Dropping a borrowing write/flush/commit wait retains its pending operation.
    /// A write retry must supply the same byte prefix until its receipt is consumed;
    /// a changed prefix fails rather than crediting an old write to new input.
    /// Dropping the sink requests cancellation of its job; the owning region still
    /// drains admitted work. A started commit may publish despite cancellation.
    /// There is no automatic checkpoint, network reconnect, or staging deletion.
    /// Use cancel with a live cleanup context to discard an uncommitted sink.
    ///
    /// Whole-file verification and filesystem/policy limits are inherited from
    /// SparseWriter. This does not confine hostile parent paths or prevent external
    /// mutation. Neither the receipt ceiling nor the one-buffer bound covers
    /// caller-owned manifest, source or TLS buffers. Backend errors remain in
    /// the io::Error source chain; cancellation/panic outcomes use non-retryable
    /// Other diagnostics. This known-manifest profile does not reconstruct a
    /// live connection's nonce, epoch chain or replay window from a disk journal.
    pub struct ManifestFileSink {
        writer: ScopedSparseWriter,
        object_id: ObjectId,
        manifest: Arc<Manifest>,
        expected: Option<ManifestChunkCommitment>,
        expected_bytes: u64,
        max_chunks: u32,
        written: u64,
        chunks: u32,
        hash: Sha256,
        checks: ChunkChecks,
        flushed: Option<u64>,
        pending: Option<Work>,
        unreported: Option<WriteReceipt>,
        receipt: Option<LiveStreamReceipt>,
        published: Option<PathBuf>,
        failure: Option<Failure>,
        shutdown: bool,
        poisoned: bool,
    }

    impl fmt::Debug for ManifestFileSink {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ManifestFileSink")
                .field("written_bytes", &self.written)
                .field("expected_bytes", &self.expected_bytes)
                .field("chunks", &self.chunks)
                .field("pending", &self.pending.is_some())
                .field("published", &self.published.is_some())
                .finish_non_exhaustive()
        }
    }

    impl ManifestFileSink {
        /// Validate local expectations, then prepare the existing scoped writer.
        /// Manifest checks and construction are offloaded. Invalid authority,
        /// identity, length, pin or bounds cannot create staging or a destination.
        pub async fn new(cx: &Cx, config: ManifestFileSinkConfig) -> io::Result<Self> {
            let (config, expected_bytes) = cx.scoped_fs().run_io(move |_| {
                let length = validate(&config)?;
                Ok((config, length))
            }).await.map_err(io::Error::other)?;
            let object_id = config.object_id.clone();
            let writer = domain(ScopedSparseWriter::new(
                cx, config.object_id, config.destination, config.writer,
            ).await)?;
            domain(writer.set_expected_size(cx, expected_bytes).await)?;
            Ok(Self {
                writer, object_id, manifest: config.manifest, expected: config.expected_chunk_commitment,
                expected_bytes, max_chunks: config.max_chunks, written: 0, chunks: 0,
                hash: Sha256::new(), checks: ChunkChecks::default(), flushed: None, pending: None, unreported: None,
                receipt: None, published: None, failure: None, shutdown: false, poisoned: false,
            })
        }

        /// Successful core write receipts observed by this sink, not peer ACKs.
        /// A still-pending write may have additional effects not yet observed here.
        #[must_use]
        pub fn written_bytes(&self) -> u64 { self.written }

        /// The actual successful local publication path, not a sender receipt.
        /// None also covers an unresolved commit error; it does NOT prove rollback.
        #[must_use]
        pub fn published_path(&self) -> Option<&Path> { self.published.as_deref() }

        /// Consume the sink and request explicit cleanup through the same writer.
        /// Any retained job is first abandoned, then the writer's admission gate
        /// waits for core execution before cleanup. Committed or uncertain
        /// publication refuses cancellation and retains its evidence. Dropping
        /// this cleanup future is not a guarantee that staging was removed.
        pub async fn cancel(self, cx: &Cx) -> io::Result<()> {
            let writer = self.writer.clone();
            drop(self);
            domain(writer.cancel(cx).await)
        }

        fn fail(&mut self, error: io::Error) -> io::Error {
            let failure = Failure(Arc::new(error));
            let reported = failure.repeat();
            self.failure = Some(failure);
            reported
        }

        fn drive(&mut self, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(error) = &self.failure {
                return Poll::Ready(Err(error.repeat()));
            }
            if self.poisoned {
                return Poll::Ready(Err(io::Error::other("manifest sink cannot repoll after panic")));
            }
            let Some(pending) = self.pending.as_mut() else { return Poll::Ready(Ok(())); };
            self.poisoned = true;
            let result = pending.as_mut().poll(task);
            self.poisoned = false;
            let Poll::Ready(result) = result else { return Poll::Pending; };
            // Retire the future before another method can observe terminal state.
            // Never repoll a Ready async function or replace an admitted job.
            self.pending = None;
            match result {
                Ok(Completion::Written { count, digest, next_hash }) => {
                    self.written += count as u64; // Bounded before admission.
                    self.chunks += 1;
                    self.hash = next_hash;
                    self.unreported = Some(WriteReceipt { count, digest });
                }
                Ok(Completion::Flushed(bytes)) => self.flushed = Some(bytes),
                Ok(Completion::Committed(path)) => self.published = Some(path),
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ManifestFileSink {
        fn poll_write(
            self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.shutdown || this.receipt.is_some() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            loop {
                match this.drive(task) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {}
                }
                if let Some(receipt) = this.unreported.take() {
                    let matches = bytes.get(..receipt.count).is_some_and(|prefix| {
                        let digest: [u8; 32] = Sha256::digest(prefix).into();
                        digest == receipt.digest
                    });
                    if !matches {
                        return Poll::Ready(Err(this.fail(invalid(
                            "pending write was repolled with a different byte prefix",
                        ))));
                    }
                    return Poll::Ready(Ok(receipt.count));
                }
                if bytes.is_empty() { return Poll::Ready(Ok(0)); }
                if this.written == this.expected_bytes {
                    return Poll::Ready(Err(this.fail(invalid("write exceeds expected manifest length"))));
                }
                if this.chunks == this.max_chunks {
                    return Poll::Ready(Err(this.fail(invalid("manifest sink write receipt limit exhausted"))));
                }
                let cx = match current_context() {
                    Ok(cx) => cx,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                let count = bytes.len().min(
                    (this.expected_bytes - this.written).min(MAX_LIVE_EPOCH_BYTES as u64) as usize,
                );
                let payload = bytes[..count].to_vec();
                let digest = Sha256::digest(&payload).into();
                let checked = match this.manifest.objects.get(&this.object_id) {
                    Some(object) => this.checks.accept(&object.chunk_boundaries, this.written, &payload, digest),
                    None => Err(integrity_error("selected manifest object is absent".to_owned())),
                };
                if let Err(error) = checked {
                    // No disk job for the completing batch, and no later method
                    // may continue a cursor partially consumed by a failed hash.
                    return Poll::Ready(Err(this.fail(error)));
                }
                let mut next_hash = this.hash.clone();
                next_hash.update(&payload);
                let writer = this.writer.clone();
                let offset = this.written;
                this.pending = Some(Box::pin(async move {
                    let range = domain(writer.write_chunk(&cx, offset, payload, WriteOptions::default()).await)?;
                    if range.offset != offset || range.size != count as u64 {
                        return Err(io::Error::other("sparse writer returned a mismatched write receipt"));
                    }
                    Ok(Completion::Written { count, digest, next_hash })
                }));
            }
        }

        fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            loop {
                match this.drive(task) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {}
                }
                if this.unreported.is_some() {
                    return Poll::Ready(Err(invalid("consume the pending write receipt before flushing")));
                }
                if this.published.is_some() || this.flushed == Some(this.written) {
                    return Poll::Ready(Ok(()));
                }
                let cx = match current_context() {
                    Ok(cx) => cx,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                let writer = this.writer.clone();
                let bytes = this.written;
                this.pending = Some(Box::pin(async move {
                    domain(writer.sync_all(&cx).await)?;
                    Ok(Completion::Flushed(bytes))
                }));
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.as_mut().poll_flush(task) {
                Poll::Ready(Ok(())) => {
                    self.get_mut().shutdown = true;
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl LiveStreamCommitSink for ManifestFileSink {
        fn poll_commit(
            self: Pin<&mut Self>, task: &mut Context<'_>, receipt: &LiveStreamReceipt,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.receipt.as_ref().is_some_and(|expected| expected != receipt) {
                // A different caller must not replace or repoll the transaction.
                // Keep the original future/receipt available for its owner's drain.
                return Poll::Ready(Err(invalid("commit receipt differs from admitted stream")));
            }
            loop {
                match this.drive(task) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {}
                }
                if this.published.is_some() { return Poll::Ready(Ok(())); }
                if this.unreported.is_some() {
                    return Poll::Ready(Err(invalid("consume the pending write receipt before commit")));
                }
                let digest: [u8; 32] = this.hash.clone().finalize().into();
                if this.written != this.expected_bytes || receipt.prefix.bytes != this.written
                    || receipt.source_sha256 != digest
                {
                    return Poll::Ready(Err(this.fail(invalid("commit receipt does not match staged stream"))));
                }
                let checked = match this.manifest.objects.get(&this.object_id) {
                    Some(object) => this.checks.finish(&object.chunk_boundaries, this.written),
                    None => Err(integrity_error("selected manifest object is absent".to_owned())),
                };
                if let Err(error) = checked {
                    return Poll::Ready(Err(this.fail(error)));
                }
                let cx = match current_context() {
                    Ok(cx) => cx,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                let writer = this.writer.clone();
                let manifest = Arc::clone(&this.manifest);
                let expected = this.expected;
                this.receipt = Some(receipt.clone());
                this.pending = Some(Box::pin(async move {
                    let result = match expected {
                        Some(expected) => writer.verify_and_commit_with_chunk_commitment(&cx, manifest, expected).await,
                        None => writer.verify_and_commit(&cx, manifest).await,
                    };
                    domain(result).map(Completion::Committed)
                }));
            }
        }
    }

    fn current_context() -> io::Result<Cx> {
        Cx::current().ok_or_else(|| io::Error::other("manifest sink requires a current native task context"))
    }

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn domain<T>(result: ScopedWriterResult<T>) -> io::Result<T> {
        match result {
            Ok(Outcome::Ok(value)) => Ok(value),
            Ok(Outcome::Err(error)) => Err(io::Error::other(error)),
            Err(error) => Err(io::Error::other(error)),
            // A sticky cancellation must not become an endlessly retried
            // Interrupted result inside AsyncWriteExt::write_all.
            Ok(Outcome::Cancelled(reason)) => Err(io::Error::other(format!("sparse writer cancelled: {reason:?}"))),
            Ok(Outcome::Panicked(payload)) => Err(io::Error::other(format!("sparse writer panicked: {payload:?}"))),
        }
    }

    fn validate(config: &ManifestFileSinkConfig) -> io::Result<u64> {
        if let Some(expected) = config.expected_chunk_commitment {
            expected.verify(&config.manifest).map_err(io::Error::other)?;
        } else {
            config.manifest.validate().map_err(io::Error::other)?;
        }
        let object = config.manifest.objects.get(&config.object_id)
            .ok_or_else(|| invalid("manifest does not contain the selected file"))?;
        if object.id != config.object_id || object.kind != ObjectKind::FileObject {
            return Err(invalid("manifest selection is not the same regular file"));
        }
        let length = object.size_bytes.ok_or_else(|| invalid("manifest file length is required"))?;
        if length > config.max_bytes || length.div_ceil(MAX_LIVE_EPOCH_BYTES as u64) > u64::from(config.max_chunks) {
            return Err(invalid("manifest file exceeds sink byte or receipt limits"));
        }
        let chunk_only = !config.object_id.is_content_addressed() && object.content_hash.is_none();
        if chunk_only && config.expected_chunk_commitment.is_none() {
            return Err(invalid("chunk-only file requires an independently trusted commitment"));
        }
        let mut covered = 0;
        for chunk in &object.chunk_boundaries {
            let end = chunk.byte_offset.checked_add(chunk.size_bytes)
                .filter(|end| *end <= length)
                .ok_or_else(|| invalid("manifest chunk lies outside the expected file"))?;
            if chunk.size_bytes == 0 {
                let empty: [u8; 32] = Sha256::digest(b"").into();
                if chunk.content_hash != empty {
                    return Err(integrity_error(format!("manifest chunk {} hash mismatch", chunk.index)));
                }
            }
            if chunk_only && (chunk.size_bytes == 0 || chunk.byte_offset != covered) {
                return Err(invalid("chunk-only manifest must cover the entire file"));
            }
            covered = end;
        }
        if chunk_only && covered != length {
            return Err(invalid("chunk-only manifest must cover the entire file"));
        }
        Ok(length)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::atp::journal::{CommitPolicy, FsyncPolicy};
        use crate::atp::object::{ContentId, MetadataPolicy, Object, ObjectGraph};
        use crate::channel::oneshot;
        use crate::io::AsyncWriteExt;
        use crate::net::atp::sdk::native_auth::live::LiveStreamPrefix;
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
        use std::future::poll_fn;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::task::Waker;
        use std::time::Duration;

        fn runtime(workers: usize, blocking: usize) -> Runtime {
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
            builder.blocking_threads(1, blocking).build().unwrap()
        }

        fn drained(runtime: &Runtime) {
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }

        fn config(data: &[u8], destination: PathBuf, policy: CommitPolicy) -> ManifestFileSinkConfig {
            let object = Object::file(data.to_vec());
            let object_id = object.id.clone();
            let mut graph = ObjectGraph::new();
            graph.add_root(object).unwrap();
            ManifestFileSinkConfig {
                object_id,
                manifest: Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap()),
                expected_chunk_commitment: None,
                destination,
                writer: SparseWriterConfig {
                    enable_preallocation: false, fsync_policy: FsyncPolicy::Never,
                    commit_policy: policy, ..SparseWriterConfig::default()
                },
                max_bytes: data.len() as u64,
                max_chunks: 100,
            }
        }

        fn receipt(data: &[u8]) -> LiveStreamReceipt {
            LiveStreamReceipt {
                prefix: LiveStreamPrefix {
                    stream_nonce: [1; 32], epochs: u64::from(!data.is_empty()),
                    bytes: data.len() as u64, chain: [2; 32],
                },
                source_sha256: Sha256::digest(data).into(),
            }
        }

        async fn commit(sink: &mut ManifestFileSink, receipt: &LiveStreamReceipt) -> io::Result<()> {
            poll_fn(|task| Pin::new(&mut *sink).poll_commit(task, receipt)).await
        }

        fn with_hints(
            mut options: ManifestFileSinkConfig, bytes: &[u8], ranges: &[(usize, usize)],
        ) -> ManifestFileSinkConfig {
            use crate::atp::manifest::{ChunkStrategy, MerkleRoot};
            let manifest = Arc::make_mut(&mut options.manifest);
            manifest.objects.get_mut(&options.object_id).unwrap().chunk_boundaries =
                ranges.iter().enumerate().map(|(index, &(start, end))| ChunkBoundary {
                    index: index as u32, byte_offset: start as u64, size_bytes: (end - start) as u64,
                    content_hash: Sha256::digest(&bytes[start..end]).into(),
                    strategy: ChunkStrategy::FixedSize, metadata: None,
                }).collect();
            manifest.merkle_root = MerkleRoot::from_manifest_components(
                &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
                &manifest.compression_policy, &manifest.encryption_policy,
                &manifest.capability_policy, &manifest.transform_order,
                &manifest.transform_proof_policy, &manifest.repair_groups,
            );
            manifest.validate().unwrap();
            options
        }

        #[test]
        fn live_chunk_cursor_agrees_with_direct_hashes_at_every_split() {
            use crate::atp::manifest::ChunkStrategy;
            let expected = b"abcdefgh";
            for start in 0..=8 {
                for end in start..=8 {
                    let boundaries = [ChunkBoundary {
                        index: 0, byte_offset: start as u64, size_bytes: (end - start) as u64,
                        content_hash: Sha256::digest(&expected[start..end]).into(),
                        strategy: ChunkStrategy::FixedSize, metadata: None,
                    }];
                    for split in 1..=9 {
                        for changed in 0..=8 {
                            let mut bytes = *expected;
                            if changed != 8 { bytes[changed] ^= 1; }
                            let mut checks = ChunkChecks::default();
                            let result = bytes.chunks(split).enumerate().try_for_each(|(index, batch)| {
                                checks.accept(&boundaries, (index * split) as u64, batch,
                                    Sha256::digest(batch).into())
                            }).and_then(|()| checks.finish(&boundaries, 8));
                            assert_eq!(result.is_ok(), !(start..end).contains(&changed),
                                "range {start}..{end}, split {split}, changed {changed}");
                        }
                    }
                }
            }
        }

        #[test]
        fn live_chunk_failure_stops_before_the_completing_write_and_stays_terminal() {
            for workers in [1, 2] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers, 2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                        for bad_prefix in [false, true] {
                            let path = directory.path().join(format!("early-{policy:?}-{bad_prefix}"));
                            cx.scoped_fs().write(path.clone(), b"original".to_vec()).await.unwrap();
                            let options = with_hints(config(b"abcdefghijkl", path.clone(), policy),
                                b"abcdefghijkl", &[(0, 6), (6, 12)]);
                            let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                            let prefix = if bad_prefix { b"Xbc" } else { b"abc" };
                            sink.write_all(prefix).await.unwrap();
                            sink.flush().await.unwrap();
                            let suffix = if bad_prefix { b"def" } else { b"Xef" };
                            let error = sink.write_all(suffix).await.unwrap_err();
                            assert_eq!(error.kind(), io::ErrorKind::Other);
                            assert!(error.to_string().contains("manifest chunk 0 hash mismatch"));
                            assert_eq!(sink.written_bytes(), 3);
                            assert_eq!(sink.chunks, 1);
                            assert!(sink.pending.is_none());
                            let stats = sink.writer.get_stats(&cx).await.unwrap().unwrap();
                            assert_eq!(stats.total_bytes_written, 3);
                            assert_eq!(stats.chunk_count, 1);
                            let hash: [u8; 32] = sink.hash.clone().finalize().into();
                            assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(prefix)));
                            assert_eq!(sink.write(b"ghijkl").await.unwrap_err().to_string(), error.to_string());
                            assert_eq!(sink.flush().await.unwrap_err().to_string(), error.to_string());
                            assert_eq!(commit(&mut sink, &receipt(b"abcdefghijkl")).await.unwrap_err().to_string(), error.to_string());
                            assert!(sink.published_path().is_none());
                            assert_eq!(std::fs::read(&path).unwrap(), b"original");
                            sink.cancel(&cx).await.unwrap();
                            assert_eq!(std::fs::read(path).unwrap(), b"original");
                        }
                    }
                });
                drained(&runtime);
            }
        }

        #[test]
        fn live_chunk_checks_preserve_valid_fragmented_publication() {
            for workers in [1, 2] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers, 2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                        for split in [1, 3, 8] {
                            let path = directory.path().join(format!("chunks-{policy:?}-{split}"));
                            let options = with_hints(config(b"abcdefgh", path.clone(), policy),
                                b"abcdefgh", &[(0, 0), (0, 2), (2, 5), (5, 8), (8, 8)]);
                            let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                            for batch in b"abcdefgh".chunks(split) {
                                sink.write_all(batch).await.unwrap();
                            }
                            sink.flush().await.unwrap();
                            assert!(!path.exists());
                            commit(&mut sink, &receipt(b"abcdefgh")).await.unwrap();
                            assert_eq!(sink.checks.next, 5);
                            assert!(sink.checks.partial.is_none());
                            assert_eq!(std::fs::read(path).unwrap(), b"abcdefgh");
                        }
                    }
                });
                drained(&runtime);
            }
        }

        #[test]
        fn invalid_empty_chunk_digest_refuses_before_any_writer_construction() {
            for data in [b"".as_slice(), b"abcdefgh".as_slice()] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(1, 2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut options = with_hints(config(data, directory.path().join("absent"), CommitPolicy::AtomicRename),
                        data, &[(data.len(), data.len())]);
                    let manifest = Arc::make_mut(&mut options.manifest);
                    manifest.objects.get_mut(&options.object_id).unwrap().chunk_boundaries[0].content_hash[0] ^= 1;
                    // Legacy root/structural validation deliberately permits this
                    // descriptor change. The new content preflight must reject it.
                    manifest.validate().unwrap();
                    let error = ManifestFileSink::new(&cx, options).await.unwrap_err();
                    assert!(error.to_string().contains("manifest chunk 0 hash mismatch"));
                    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
                });
                drained(&runtime);
            }
        }

        #[test]
        fn partial_live_hints_cannot_replace_final_whole_object_authentication() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2, 2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = directory.path().join("partial-hints");
                cx.scoped_fs().write(path.clone(), b"original".to_vec()).await.unwrap();
                let options = with_hints(config(b"abcdefgh", path.clone(), CommitPolicy::CopyAndVerify),
                    b"abcdefgh", &[(1, 3), (5, 7)]);
                let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                sink.write_all(b"XbcdYfgZ").await.unwrap();
                assert_eq!(sink.checks.next, 2);
                assert_eq!(sink.written_bytes(), 8);
                let error = commit(&mut sink, &receipt(b"XbcdYfgZ")).await.unwrap_err();
                assert!(error.to_string().contains("hash mismatch"));
                assert!(sink.published_path().is_none());
                assert_eq!(std::fs::read(&path).unwrap(), b"original");
                sink.cancel(&cx).await.unwrap();
            });
            drained(&runtime);
        }

        #[test]
        fn dropped_write_wait_preserves_a_crossing_manifest_hash() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2, 1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = directory.path().join("crossing-hash");
                let options = with_hints(config(b"abcdefgh", path.clone(), CommitPolicy::AtomicRename),
                    b"abcdefgh", &[(0, 8)]);
                let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                sink.write_all(b"abc").await.unwrap();
                assert!(sink.checks.partial.is_some());
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
                let mut writing = Box::pin(sink.write_all(b"def"));
                poll_fn(|task| { assert!(writing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                drop(writing);
                assert!(sink.pending.is_some());
                assert_eq!(sink.written_bytes(), 3);
                release.send(()).unwrap();
                blocker.await.unwrap();
                sink.write_all(b"def").await.unwrap();
                assert_eq!(sink.written_bytes(), 6);
                sink.write_all(b"gh").await.unwrap();
                assert_eq!(sink.chunks, 3);
                assert_eq!(sink.checks.next, 1);
                assert!(sink.checks.partial.is_none());
                commit(&mut sink, &receipt(b"abcdefgh")).await.unwrap();
                assert_eq!(std::fs::read(path).unwrap(), b"abcdefgh");
            });
            drained(&runtime);
        }

        struct CountingSource {
            data: &'static [u8],
            position: usize,
            consumed: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl crate::io::AsyncRead for CountingSource {
            fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut crate::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
                let count = buf.remaining().min(self.data.len() - self.position);
                buf.put_slice(&self.data[self.position..self.position + count]);
                self.position += count;
                self.consumed.store(self.position, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
        }

        #[test]
        fn real_mtls_chunk_mismatch_stops_the_sender_before_its_second_epoch() {
            use crate::net::atp::sdk::{AtpSdk, NativeClientAuthorization, NativeClientCertificateId, SessionConfig};
            use crate::net::atp::sdk::native_auth::live::{LiveStreamConfig, LiveStreamError};
            use rustls::pki_types::ServerName;
            for workers in [1, 2] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers, 2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let sdk = AtpSdk::new_in_process(SessionConfig { max_concurrent_transfers: 1, ..SessionConfig::default() });
                    let roots = || { let mut roots = rustls::RootCertStore::empty(); roots.add(certificate("ca")).unwrap(); roots };
                    let mut options = LiveStreamConfig::default();
                    options.epoch_bytes = 4;
                    options.max_bytes = 12;
                    options.operation_timeout = Duration::from_secs(5);
                    let sender = sdk.live_stream_sender(options.clone(), ServerName::try_from("localhost").unwrap(), roots(), identity("allowed")).unwrap();
                    let client = NativeClientCertificateId::from_certificate(&certificate("allowed"));
                    let receiver = sdk.live_stream_receiver(options, identity("server"), NativeClientAuthorization::new(roots(), [client]).unwrap()).unwrap();
                    let listener = receiver.bind(&cx, "127.0.0.1:0".parse().unwrap()).await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let path = directory.path().join("early-network");
                    cx.scoped_fs().write(path.clone(), b"original".to_vec()).await.unwrap();
                    let options = with_hints(config(b"abcdefghijkl", path.clone(), CommitPolicy::CopyAndVerify),
                        b"abcdefghijkl", &[(0, 4), (4, 12)]);
                    let sink = ManifestFileSink::new(&cx, options).await.unwrap();
                    let gate = Arc::new(Gate::default());
                    // A pre-fix receiver must not hang at this test boundary;
                    // it reaches finalization and fails the assertions below.
                    gate.released.store(true, Ordering::SeqCst);
                    let mut receiving = listener.spawn_receive_committing(&cx, &scope,
                        GatedSink { inner: sink, gate: Arc::clone(&gate) }).unwrap();
                    let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let source = CountingSource { data: b"Xbcdefghijkl", position: 0, consumed: Arc::clone(&consumed) };
                    let mut sending = sender.spawn_send_reader(&cx, &scope, address, source).unwrap();
                    let (sent, received) = futures_lite::future::zip(sending.join(&cx), receiving.join(&cx)).await;
                    let received = received.unwrap();
                    assert!(sent.unwrap().outcome.is_err(), "no final peer Proof for refused data");
                    assert!(matches!(received.outcome, Err(LiveStreamError::Io(error))
                        if error.kind() == io::ErrorKind::Other && error.to_string().contains("manifest chunk 0 hash mismatch")));
                    assert_eq!(received.sink_written_bytes, 0);
                    let prefix = received.prefix.expect("authenticated hello completed");
                    assert_eq!(prefix.bytes, 0);
                    assert_eq!(prefix.epochs, 0);
                    assert_eq!(consumed.load(Ordering::SeqCst), 4, "do not read the next source epoch");
                    assert!(!gate.entered.load(Ordering::SeqCst), "never invoke application commit");
                    assert_eq!(std::fs::read(path).unwrap(), b"original");
                    assert_eq!(receiver.active_streams(), 0);
                });
                drained(&runtime);
            }
        }

        #[test]
        fn large_writes_use_bounded_receipts_without_publishing_on_flush() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2, 2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let data: Vec<u8> = (0..2 * MAX_LIVE_EPOCH_BYTES + 7)
                    .map(|index| (index % 251) as u8).collect();
                let path = directory.path().join("bounded-write");
                let mut options = config(&data, path.clone(), CommitPolicy::CopyAndVerify);
                options.max_chunks = 3;
                let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                assert_eq!(sink.write(&data).await.unwrap(), MAX_LIVE_EPOCH_BYTES);
                assert_eq!(sink.write(&data[MAX_LIVE_EPOCH_BYTES..]).await.unwrap(), MAX_LIVE_EPOCH_BYTES);
                assert_eq!(sink.write(&data[2 * MAX_LIVE_EPOCH_BYTES..]).await.unwrap(), 7);
                assert_eq!(sink.written_bytes(), data.len() as u64);
                assert_eq!(sink.chunks, 3);
                assert_eq!(sink.writer.get_stats(&cx).await.unwrap().unwrap().chunk_count, 3);
                sink.flush().await.unwrap();
                assert!(!path.exists());
                commit(&mut sink, &receipt(&data)).await.unwrap();
                assert_eq!(std::fs::read(path).unwrap(), data);
            });
            drained(&runtime);
        }

        #[test]
        fn live_manifest_sink_flush_does_not_publish_and_commit_uses_canonical_verifier() {
            for workers in [1, 2] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(workers, 2);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                        for data in [b"".as_slice(), b"abcdefgh".as_slice()] {
                            let path = directory.path().join(format!("{policy:?}-{}", data.len()));
                            let mut sink = ManifestFileSink::new(&cx, config(data, path.clone(), policy)).await.unwrap();
                            for part in data.chunks(3) {
                                sink.write_all(part).await.unwrap();
                                sink.flush().await.unwrap();
                                assert!(!path.exists());
                                assert!(sink.published_path().is_none());
                            }
                            sink.shutdown().await.unwrap();
                            assert!(!path.exists(), "shutdown is not manifest authorization");
                            assert_eq!(sink.written_bytes(), data.len() as u64);
                            let expected = receipt(data);
                            commit(&mut sink, &expected).await.unwrap();
                            assert_eq!(sink.published_path(), Some(path.as_path()));
                            assert_eq!(std::fs::read(&path).unwrap(), data);
                            commit(&mut sink, &expected).await.unwrap();
                            let mut other = expected.clone();
                            other.prefix.stream_nonce[0] ^= 1;
                            assert_eq!(commit(&mut sink, &other).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
                            assert_eq!(sink.write(b"x").await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
                        }
                    }
                });
                drained(&runtime);
            }
        }

        #[test]
        fn valid_live_hash_cannot_override_expected_content_or_a_pinned_manifest() {
            use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
            use crate::atp::object::ManifestId;
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2, 2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                for pinned in [false, true] {
                    for corrupt in [false, true] {
                        let path = directory.path().join(format!("integrity-{pinned}-{corrupt}"));
                        cx.scoped_fs().write(path.clone(), b"original destination".to_vec()).await.unwrap();
                        let mut options = config(b"abcdefgh", path.clone(), CommitPolicy::CopyAndVerify);
                        if pinned {
                            let manifest = Arc::make_mut(&mut options.manifest);
                            let mut object = manifest.objects.remove(&options.object_id).unwrap();
                            options.object_id = ObjectId::manifest(ManifestId::from_manifest_bytes(b"live-manifest-file"));
                            object.id = options.object_id.clone();
                            object.content_hash = None;
                            object.chunk_boundaries = b"abcdefgh".chunks(4).enumerate().map(|(index, part)| ChunkBoundary {
                                index: index as u32, byte_offset: (index * 4) as u64, size_bytes: part.len() as u64,
                                content_hash: Sha256::digest(part).into(), strategy: ChunkStrategy::FixedSize, metadata: None,
                            }).collect();
                            manifest.objects.insert(options.object_id.clone(), object);
                            manifest.roots = vec![options.object_id.clone()];
                            manifest.merkle_root = MerkleRoot::from_manifest_components(
                                &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
                                &manifest.compression_policy, &manifest.encryption_policy,
                                &manifest.capability_policy, &manifest.transform_order,
                                &manifest.transform_proof_policy, &manifest.repair_groups,
                            );
                            options.expected_chunk_commitment = Some(ManifestChunkCommitment::from_manifest(manifest).unwrap());
                        }
                        let data = if corrupt { b"tampered" } else { b"abcdefgh" };
                        let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                        if corrupt && pinned {
                            // Chunk commitments reject before accepting the bad
                            // batch, rather than postponing failure until commit.
                            let error = sink.write_all(data).await.unwrap_err();
                            assert_eq!(error.kind(), io::ErrorKind::Other);
                            assert!(error.to_string().contains("hash mismatch"));
                            assert_eq!(sink.written_bytes(), 0);
                            assert_eq!(sink.writer.get_stats(&cx).await.unwrap().unwrap().chunk_count, 0);
                            assert_eq!(sink.flush().await.unwrap_err().to_string(), error.to_string());
                            assert_eq!(commit(&mut sink, &receipt(data)).await.unwrap_err().to_string(), error.to_string());
                            assert!(sink.published_path().is_none());
                            assert_eq!(std::fs::read(&path).unwrap(), b"original destination");
                            sink.cancel(&cx).await.unwrap();
                            continue;
                        }
                        sink.write_all(data).await.unwrap();
                        sink.flush().await.unwrap();
                        assert_eq!(std::fs::read(&path).unwrap(), b"original destination");
                        let result = commit(&mut sink, &receipt(data)).await;
                        if corrupt {
                            let error = result.unwrap_err();
                            assert_eq!(error.kind(), io::ErrorKind::Other);
                            assert!(error.to_string().contains("hash mismatch"));
                            assert_eq!(commit(&mut sink, &receipt(data)).await.unwrap_err().to_string(), error.to_string());
                            assert!(sink.published_path().is_none());
                            assert_eq!(std::fs::read(&path).unwrap(), b"original destination");
                            sink.cancel(&cx).await.unwrap();
                        } else {
                            result.unwrap();
                            assert_eq!(std::fs::read(&path).unwrap(), data);
                        }
                    }
                }
            });
            drained(&runtime);
        }

        #[test]
        fn manifest_sink_preflight_and_stream_limits_refuse_without_false_progress() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1, 2);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                for case in 0..4 {
                    let mut options = config(b"abcdefgh", directory.path().join("absent"), CommitPolicy::AtomicRename);
                    match case {
                        0 => options.max_bytes = 7,
                        1 => options.max_chunks = 0,
                        2 => options.expected_chunk_commitment = Some(ManifestChunkCommitment::new([0; 32])),
                        3 => options.object_id = ObjectId::content(ContentId::from_bytes(b"other")),
                        _ => unreachable!(),
                    }
                    assert!(ManifestFileSink::new(&cx, options).await.is_err());
                    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
                }
                let path = directory.path().join("quota");
                let mut options = config(b"abcdefgh", path.clone(), CommitPolicy::AtomicRename);
                options.max_chunks = 1;
                let mut sink = ManifestFileSink::new(&cx, options).await.unwrap();
                sink.write_all(b"abcd").await.unwrap();
                assert_eq!(sink.write(b"efgh").await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
                assert_eq!(sink.written_bytes(), 4);
                assert!(!path.exists());
                assert!(commit(&mut sink, &receipt(b"abcdefgh")).await.is_err());
                sink.cancel(&cx).await.unwrap();
                let path = directory.path().join("oversized");
                let mut sink = ManifestFileSink::new(&cx, config(b"abcd", path.clone(), CommitPolicy::AtomicRename)).await.unwrap();
                assert_eq!(sink.write(b"abcdefgh").await.unwrap(), 4);
                assert_eq!(sink.write(b"efgh").await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
                assert_eq!(sink.written_bytes(), 4);
                assert!(!path.exists());
            });
            drained(&runtime);
        }

        #[test]
        fn dropped_write_wait_keeps_one_owned_buffer_and_rejects_a_changed_retry() {
            for changed in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = runtime(2, 1);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let path = directory.path().join("retained-write");
                    let mut sink = ManifestFileSink::new(&cx, config(b"abcdefgh", path.clone(), CommitPolicy::AtomicRename)).await.unwrap();
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
                    let mut writing = Box::pin(sink.write_all(b"abcdefgh"));
                    poll_fn(|task| { assert!(writing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                    drop(writing);
                    assert!(sink.pending.is_some());
                    assert_eq!(sink.written_bytes(), 0);
                    release.send(()).unwrap();
                    blocker.await.unwrap();
                    let data = if changed { b"tampered" } else { b"abcdefgh" };
                    let result = sink.write_all(data).await;
                    assert_eq!(sink.written_bytes(), 8);
                    assert_eq!(sink.chunks, 1, "do not submit the old bytes twice");
                    if changed {
                        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
                        assert!(commit(&mut sink, &receipt(data)).await.is_err());
                        assert!(!path.exists());
                    } else {
                        result.unwrap();
                        commit(&mut sink, &receipt(data)).await.unwrap();
                        assert_eq!(std::fs::read(path).unwrap(), data);
                    }
                });
                drained(&runtime);
            }
        }

        #[test]
        fn polling_authority_is_not_inherited_from_the_constructor() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(1, 1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = directory.path().join("authority");
                let mut sink = ManifestFileSink::new(&cx, config(b"data", path.clone(), CommitPolicy::AtomicRename)).await.unwrap();
                let error = poll_fn(|task| {
                    let _restricted = cx.restrict::<crate::cx::NoCaps>().set_current_restricted();
                    Pin::new(&mut sink).poll_write(task, b"data")
                }).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert_eq!(sink.written_bytes(), 0);
                assert!(sink.pending.is_none());
                assert!(!path.exists());
                assert_eq!(sink.writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 0);
                sink.cancel(&cx).await.unwrap();
            });
            drained(&runtime);
        }

        #[test]
        fn dropped_commit_wait_retains_the_original_receipt_and_transaction() {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(2, 1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = directory.path().join("retained-commit");
                let mut sink = ManifestFileSink::new(&cx, config(b"data", path.clone(), CommitPolicy::AtomicRename)).await.unwrap();
                sink.write_all(b"data").await.unwrap();
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
                let expected = receipt(b"data");
                let mut committing = Box::pin(commit(&mut sink, &expected));
                poll_fn(|task| { assert!(committing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                drop(committing);
                let mut wrong = expected.clone();
                wrong.prefix.chain[0] ^= 1;
                assert_eq!(commit(&mut sink, &wrong).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
                assert!(sink.pending.is_some());
                assert!(!path.exists());
                release.send(()).unwrap();
                blocker.await.unwrap();
                commit(&mut sink, &expected).await.unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), b"data");
                // An idempotent observation must not republish over a later file.
                cx.scoped_fs().write(path.clone(), b"later".to_vec()).await.unwrap();
                commit(&mut sink, &expected).await.unwrap();
                assert_eq!(std::fs::read(path).unwrap(), b"later");
            });
            drained(&runtime);
        }

        #[derive(Default)]
        struct Gate {
            entered: AtomicBool,
            released: AtomicBool,
            wake: parking_lot::Mutex<Option<Waker>>,
        }

        struct GatedSink { inner: ManifestFileSink, gate: Arc<Gate> }
        impl AsyncWrite for GatedSink {
            fn poll_write(mut self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.inner).poll_write(task, bytes)
            }
            fn poll_flush(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(task)
            }
            fn poll_shutdown(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(task)
            }
        }
        impl LiveStreamCommitSink for GatedSink {
            fn poll_commit(mut self: Pin<&mut Self>, task: &mut Context<'_>, receipt: &LiveStreamReceipt) -> Poll<io::Result<()>> {
                *self.gate.wake.lock() = Some(task.waker().clone());
                self.gate.entered.store(true, Ordering::SeqCst);
                if !self.gate.released.load(Ordering::SeqCst) { return Poll::Pending; }
                Pin::new(&mut self.inner).poll_commit(task, receipt)
            }
        }

        // Existing, explicitly public test identities; no generated trust bypass.
        fn certificate(name: &str) -> rustls::pki_types::CertificateDer<'static> {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            let fixtures: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/atp_native_auth_identities.json",
            ))).unwrap();
            let text = if name == "ca" { &fixtures["ca"] } else { &fixtures["identities"][name]["certificate"] };
            CertificateDer::pem_reader_iter(&mut io::BufReader::new(text.as_str().unwrap().as_bytes()))
                .next().unwrap().unwrap()
        }

        fn identity(name: &str) -> crate::net::atp::sdk::NativeTlsIdentity {
            use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
            let fixtures: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/atp_native_auth_identities.json",
            ))).unwrap();
            let text = fixtures["identities"][name]["key"].as_str().unwrap();
            let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(text.as_bytes())).next().unwrap().unwrap();
            crate::net::atp::sdk::NativeTlsIdentity::new(vec![certificate(name)], key).unwrap()
        }

        #[test]
        fn real_mtls_receiver_requires_manifest_publication_before_sender_proof() {
            use crate::net::atp::sdk::{AtpSdk, NativeClientAuthorization, NativeClientCertificateId, SessionConfig};
            use crate::net::atp::sdk::native_auth::live::{LiveStreamConfig, LiveStreamError};
            use rustls::pki_types::ServerName;
            for workers in [1, 2] {
                for corrupt in [false, true] {
                    let directory = tempfile::tempdir().unwrap();
                    let runtime = runtime(workers, 2);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let scope = cx.scope();
                        let sdk = AtpSdk::new_in_process(SessionConfig { max_concurrent_transfers: 1, ..SessionConfig::default() });
                        let roots = || { let mut roots = rustls::RootCertStore::empty(); roots.add(certificate("ca")).unwrap(); roots };
                        let mut options = LiveStreamConfig::default();
                        options.epoch_bytes = 4;
                        options.max_bytes = 8;
                        options.operation_timeout = Duration::from_secs(5);
                        let sender = sdk.live_stream_sender(options.clone(), ServerName::try_from("localhost").unwrap(), roots(), identity("allowed")).unwrap();
                        let client = NativeClientCertificateId::from_certificate(&certificate("allowed"));
                        let receiver = sdk.live_stream_receiver(options, identity("server"), NativeClientAuthorization::new(roots(), [client]).unwrap()).unwrap();
                        let listener = receiver.bind(&cx, "127.0.0.1:0".parse().unwrap()).await.unwrap();
                        let address = listener.local_addr().unwrap();
                        let path = directory.path().join("received");
                        let sink = ManifestFileSink::new(&cx, config(b"abcdefgh", path.clone(), CommitPolicy::CopyAndVerify)).await.unwrap();
                        let gate = Arc::new(Gate::default());
                        let mut receiving = listener.spawn_receive_committing(&cx, &scope, GatedSink { inner: sink, gate: Arc::clone(&gate) }).unwrap();
                        let data: &'static [u8] = if corrupt { b"tampered" } else { b"abcdefgh" };
                        let mut sending = sender.spawn_send_reader(&cx, &scope, address, data).unwrap();
                        crate::time::timeout(cx.now(), Duration::from_secs(5), async {
                            while !gate.entered.load(Ordering::SeqCst) { crate::runtime::yield_now().await; }
                        }).await.expect("real receiver never reached final commit");
                        assert!(!path.exists());
                        assert!(!sending.is_finished(), "epoch flush must not produce final peer Proof");
                        assert!(!receiving.is_finished());
                        gate.released.store(true, Ordering::SeqCst);
                        let wake = gate.wake.lock().take();
                        if let Some(wake) = wake { wake.wake(); }
                        let (sent, received) = futures_lite::future::zip(sending.join(&cx), receiving.join(&cx)).await;
                        let sent = sent.unwrap();
                        let received = received.unwrap();
                        if corrupt {
                            assert!(sent.outcome.is_err());
                            assert!(matches!(received.outcome, Err(LiveStreamError::Commit(error))
                                if matches!(*error, super::super::LiveStreamCommitError::Unconfirmed { .. })));
                            assert!(!path.exists());
                        } else {
                            assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
                            assert_eq!(std::fs::read(&path).unwrap(), data);
                        }
                        assert_eq!(receiver.active_streams(), 0);
                    });
                    drained(&runtime);
                }
            }
        }
    }
}
