//! Exact-length stream ingestion using the existing chunk reader and file owner.

use super::*;
use crate::atp::journal::{ScopedReceive, ScopedReceiveError, ScopedReceiveOptions, ScopedReceiveResult};
use crate::io::{AsyncRead, AsyncReadExt};
use crate::net::atp::chunk::profiles::ChunkingProfile as _;
use crate::net::atp::chunk::reader::StreamChunkReader;
use crate::net::atp::chunk::stream::StreamProfile;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

#[path = "receive_resume.rs"]
mod resume;

impl ScopedSparseWriter {
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
    ///
    /// Construction is lazy and returns `InvalidInput` for an invalid chunk size
    /// without polling the source. The session retains its context. A terminal
    /// cancellation/error cannot be retried as a new body or on another context;
    /// only abandonment of a borrowing wait is resumable.
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
        self.receive_session(cx, source, manifest, options, None)
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
        self.receive_session(cx, source, manifest, options, Some(expected))
    }

    fn receive_session<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
        expected: Option<ManifestChunkCommitment>,
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
            let outcome = writer.receive_body(&cx, &mut source, manifest, options, expected, progress).await?;
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
    ) -> Result<(OwnedSemaphorePermit, Outcome<T, SparseWriterError>), ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> Outcome<T, SparseWriterError> + Send + 'static,
        T: Send + 'static,
    {
        let writer = Arc::clone(&self.writer);
        cx.scoped_fs().run_io(move |_| {
            let outcome = operation(&writer);
            Ok((permit, outcome))
        }).await
    }

    async fn receive_body<R, Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &mut R,
        manifest: Arc<Manifest>,
        options: ScopedReceiveOptions,
        expected: Option<ManifestChunkCommitment>,
        accepted: Arc<AtomicU64>,
    ) -> ScopedReceiveResult<PathBuf>
    where
        R: AsyncRead + Unpin + Send,
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        let permit = self.reserve(cx).await?;
        let preflight_manifest = Arc::clone(&manifest);
        let (mut permit, preflight) = self.receive_step(cx, permit, move |writer| {
            prepare_receive(writer, &preflight_manifest, options, expected.as_ref())
        }).await?;
        let length = match preflight {
            Outcome::Ok(length) => length,
            Outcome::Err(error) => return Ok(Outcome::Err(error)),
            Outcome::Cancelled(reason) => return Ok(Outcome::Cancelled(reason)),
            Outcome::Panicked(payload) => return Ok(Outcome::Panicked(payload)),
        };
        let limited = source.take(length);
        let mut chunks = StreamChunkReader::new(limited, options.chunk_size)
            .map_err(ScopedReceiveError::Source)?;
        let mut offset = 0_u64;
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
            let (returned, written) = self.receive_step(cx, permit, move |writer| {
                writer.write_chunk_blocking(offset, &chunk.bytes, WriteOptions::default())
            }).await?;
            permit = returned;
            match written {
                Outcome::Ok(_) => {
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
        let (_permit, result) = self.receive_step(cx, permit, move |writer| {
            match writer.verify_inner(&manifest, expected.as_ref()) {
                Outcome::Ok(()) => writer.commit_with_fsync(File::sync_all),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            }
        }).await?;
        Ok(result)
    }
}

fn prepare_receive(
    writer: &SparseWriter,
    manifest: &Manifest,
    options: ScopedReceiveOptions,
    expected: Option<&ManifestChunkCommitment>,
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
            if state.temp_file.is_some() || state.temp_path.is_some() || !state.written_chunks.is_empty() {
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
            if size > options.max_bytes || size.div_ceil(options.chunk_size as u64) > u64::from(options.max_chunks) {
                return Err(invalid("receive object exceeds byte or chunk limit".to_owned()));
            }
            if object.content_hash.is_none() && !object.id.is_content_addressed() {
                if expected.is_none() {
                    return Err(invalid("chunk-only receive requires a trusted commitment".to_owned()));
                }
                SparseWriter::require_complete_manifest_chunks(&object.chunk_boundaries, size)
                    .map_err(invalid)?;
            }
            size
        };
        writer.set_expected_size(length)?;
        Ok(length)
    };
    match prepare() {
        Ok(length) => Outcome::Ok(length),
        Err(error) => Outcome::Err(error),
    }
}

#[cfg(test)]
#[path = "receive_tests.rs"]
mod tests;
