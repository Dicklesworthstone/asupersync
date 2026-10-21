//! Payload-bounded backing storage for TCP delta reception.
//!
//! Baseline planning retains verified coverage and file ranges, not file bytes.
//! Every reused range is re-read and hash-checked before reconstruction. A path
//! changed since discovery can fail the transfer; it cannot authorize different
//! content. This is not a filesystem snapshot or a path-confinement API.
//!
//! Baseline rereads admit only plain regular files. The path and the opened
//! handle are checked before seeking, allocating a chunk, or reading content.
//! Unix opens additionally refuse final symlinks and do not wait for a FIFO
//! writer; Windows opens and rejects final reparse points rather than following
//! them. These leaf/type checks do not confine ancestor paths, pin an inode,
//! or impose a deadline on an ordinary filesystem call.
//!
//! Pending storage waits observe cancellation independently of filesystem
//! completion. Started blocking syscalls may still finish after a wait ends;
//! this is soft cancellation, not syscall preemption or region-owned draining.
//! A spool whose cursor may have moved stays failed after an interrupted wait.
//!
//! Baseline open, seek, bounded reads and content verification run on the
//! blocking pool. A job reads at most one validated chunk (1 MiB) and makes at
//! most 64 read attempts. Short or interrupted reads carry the same allocation
//! and file into the next job; no job reads past the indexed range. These are
//! byte/attempt bounds, not syscall-time bounds.

use super::{ContentId, Cx, DeltaContentKey, MAX_COMPRESSED_CHUNK_RAW, TransportError};
use crate::net::atp::transport_common::delta::read_full_chunk;
use crate::net::atp::transport_common::read_bounded_chunk;
use std::future::{Future, poll_fn};
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

#[derive(Debug, Clone)]
pub(super) struct BaselineChunk {
    path: Arc<PathBuf>,
    offset: u64,
}

impl BaselineChunk {
    #[must_use]
    pub(super) fn new(path: Arc<PathBuf>, offset: u64) -> Self {
        Self { path, offset }
    }

    pub(super) async fn read_verified(
        &self,
        cx: &Cx,
        key: &DeltaContentKey,
        scratch: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        run_io(cx, async {
            check_io(cx)?;
            let length = chunk_length(key)?;
            self.offset
                .checked_add(key.size_bytes)
                .ok_or_else(|| TransportError::Frame("delta baseline range overflows u64".into()))?;
            let path = Arc::clone(&self.path);
            let offset = self.offset;
            let key = key.clone();
            // The allocation moves into the worker instead of being copied
            // into a new 128 KiB buffer for every File::poll_read handoff.
            let buffer = std::mem::take(scratch);
            let mut state = crate::runtime::spawn_blocking(move || {
                BaselineRead::open(path, offset, key, buffer, length)?.read_batch()
            })
            .await?;
            while state.reader.is_some() {
                // Also yield in the deterministic inline blocking fallback:
                // an EINTR-only source must not spin through ready jobs.
                crate::runtime::yield_now().await;
                check_io(cx)?;
                state = crate::runtime::spawn_blocking(move || state.read_batch()).await?;
            }
            *scratch = state.buffer;
            Ok(())
        })
        .await
    }
}

/// Owned state crossing a baseline blocking-pool boundary. Generic only so
/// short reads/EINTR can be tested through the same production batch method.
struct BaselineRead<R> {
    reader: Option<R>,
    path: Arc<PathBuf>,
    key: DeltaContentKey,
    buffer: Vec<u8>,
    filled: usize,
}

impl BaselineRead<std::fs::File> {
    fn open(
        path: Arc<PathBuf>,
        offset: u64,
        key: DeltaContentKey,
        mut buffer: Vec<u8>,
        length: usize,
    ) -> Result<Self, TransportError> {
        use std::io::Seek as _;

        let source_error =
            |error| TransportError::Source(format!("{}: {error}", path.display()));
        let mut file = open_baseline_file(path.as_path()).map_err(source_error)?;
        file.seek(std::io::SeekFrom::Start(offset)).map_err(source_error)?;
        buffer.resize(length, 0);
        Ok(Self {
            reader: Some(file),
            path,
            key,
            buffer,
            filled: 0,
        })
    }
}

/// Discovery classified this path earlier, but it may have been replaced while
/// the peer was sending its missing chunks. A content hash only helps after a
/// read completes: it cannot make a FIFO open or a device read safe.
fn open_baseline_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    require_regular_baseline(&std::fs::symlink_metadata(path)?)?;
    open_baseline_handle(path)
}

/// Keep the native open and descriptor check together. Path metadata above is
/// an early refusal, not authority to trust whatever a later open returns.
fn open_baseline_handle(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the final entry itself, never
        // follow it before the handle's reparse attribute can be checked.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    require_regular_baseline(&file.metadata()?)?;
    Ok(file)
}

fn require_regular_baseline(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    let regular = metadata.is_file() && !metadata.file_type().is_symlink();
    #[cfg(windows)]
    let regular = {
        use std::os::windows::fs::MetadataExt as _;
        // FILE_ATTRIBUTE_REPARSE_POINT includes junctions and non-symlink tags.
        regular && metadata.file_attributes() & 0x0000_0400 == 0
    };
    if !regular {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "delta baseline source must be a plain regular file",
        ));
    }
    Ok(())
}

impl<R: std::io::Read> BaselineRead<R> {
    fn read_batch(mut self) -> Result<Self, TransportError> {
        if let Some(reader) = self.reader.as_mut() {
            let (count, eof) = read_bounded_chunk(reader, &mut self.buffer[self.filled..])
                .map_err(|error| {
                    TransportError::Source(format!("{}: {error}", self.path.display()))
                })?;
            self.filled += count;
            if self.filled == self.buffer.len() {
                // Hash and close on the worker, before bytes are published to
                // reconstruction. Completion requires no read past the range.
                verify_bytes(&self.key, &self.buffer)?;
                self.reader = None;
            } else if eof {
                return Err(TransportError::Source(format!(
                    "{}: delta baseline range ended after {} of {} bytes",
                    self.path.display(), self.filled, self.buffer.len(),
                )));
            }
        }
        Ok(self)
    }
}

/// Check the polling caller before installing the explicit owner's context.
/// Otherwise a restricted caller could resume a parked operation with the
/// stronger authority captured when it was first created. The observer is
/// owned by this wait and is dropped on every exit, including abandonment.
async fn run_io<T>(
    cx: &Cx,
    operation: impl Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    let mut stopped = pin!(cx.cancelled());
    let mut operation = pin!(cx.with_ambient(operation));
    poll_fn(|task| {
        if let Err(error) = crate::cx::io_gate::require_ambient_io("atp::delta_storage") {
            return Poll::Ready(Err(TransportError::Io(error)));
        }
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        match operation.as_mut().poll(task) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                // Register after the first poll to close the check/register
                // race. A masked request neither aborts nor self-wakes a
                // parked syscall; checkpoint remains the authority to stop.
                if stopped.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                    return Poll::Ready(Err(TransportError::Cancelled));
                }
                Poll::Pending
            }
        }
    })
    .await
}

fn check_io(cx: &Cx) -> Result<(), TransportError> {
    cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
    crate::cx::io_gate::require_ambient_io("atp::delta_storage")?;
    Ok(())
}

fn chunk_length(key: &DeltaContentKey) -> Result<usize, TransportError> {
    if key.size_bytes == 0 || key.size_bytes > u64::from(MAX_COMPRESSED_CHUNK_RAW) {
        return Err(TransportError::Frame(
            "invalid delta storage chunk size".into(),
        ));
    }
    usize::try_from(key.size_bytes)
        .map_err(|_| TransportError::Frame("delta storage chunk exceeds usize::MAX".into()))
}

pub(super) fn verify_bytes(key: &DeltaContentKey, bytes: &[u8]) -> Result<(), TransportError> {
    let length = chunk_length(key)?;
    if bytes.len() != length || ContentId::from_bytes(bytes).to_hex() != key.content_id_hex {
        return Err(TransportError::Integrity(
            "delta stored chunk size or content id mismatch".into(),
        ));
    }
    Ok(())
}

pub(super) struct DeltaChunkSpool {
    file: crate::fs::File,
    offsets: std::collections::BTreeMap<DeltaContentKey, u64>,
    written: u64,
    limit: u64,
    phase: SpoolPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpoolPhase {
    Writing,
    Reading,
    Failed,
}

impl DeltaChunkSpool {
    pub(super) async fn create(
        cx: &Cx,
        path: &std::path::Path,
        limit: u64,
    ) -> Result<Self, TransportError> {
        run_io(cx, async {
            check_io(cx)?;
            let file = super::create_owned_staging_file(path).await?;
            Ok(Self {
                file,
                offsets: std::collections::BTreeMap::new(),
                written: 0,
                limit,
                phase: SpoolPhase::Writing,
            })
        })
        .await
    }

    #[must_use]
    pub(super) fn contains(&self, key: &DeltaContentKey) -> bool {
        self.offsets.contains_key(key)
    }

    pub(super) async fn insert(
        &mut self,
        cx: &Cx,
        key: DeltaContentKey,
        bytes: &[u8],
    ) -> Result<(), TransportError> {
        use crate::io::AsyncWriteExt as _;
        run_io(cx, async {
            check_io(cx)?;
            self.require_phase(SpoolPhase::Writing)?;
            verify_bytes(&key, bytes)?;
            if self.offsets.contains_key(&key) {
                return Ok(());
            }
            let end = self
                .written
                .checked_add(key.size_bytes)
                .ok_or_else(|| TransportError::Frame("delta spool length overflows u64".into()))?;
            if end > self.limit {
                return Err(TransportError::TooLarge {
                    size: end,
                    max: self.limit,
                });
            }
            self.phase = SpoolPhase::Failed;
            self.file.write_all(bytes).await?;
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            self.offsets.insert(key, self.written);
            self.written = end;
            self.phase = SpoolPhase::Writing;
            Ok(())
        })
        .await
    }

    pub(super) async fn seal(&mut self, cx: &Cx) -> Result<(), TransportError> {
        use crate::io::AsyncWriteExt as _;
        run_io(cx, async {
            check_io(cx)?;
            if self.phase == SpoolPhase::Reading {
                return Ok(());
            }
            self.require_phase(SpoolPhase::Writing)?;
            self.phase = SpoolPhase::Failed;
            self.file.flush().await?;
            self.phase = SpoolPhase::Reading;
            Ok(())
        })
        .await
    }

    pub(super) async fn read_verified(
        &mut self,
        cx: &Cx,
        key: &DeltaContentKey,
        scratch: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        run_io(cx, async {
            check_io(cx)?;
            self.require_phase(SpoolPhase::Reading)?;
            let length = chunk_length(key)?;
            let offset = *self.offsets.get(key).ok_or_else(|| {
                TransportError::Frame("delta spool is missing the requested chunk".into())
            })?;
            self.phase = SpoolPhase::Failed;
            self.file.seek(std::io::SeekFrom::Start(offset)).await?;
            scratch.resize(length, 0);
            let read = read_full_chunk(&mut self.file, scratch).await?;
            if read != length {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "delta spool ended before the indexed chunk was complete",
                )));
            }
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            verify_bytes(key, scratch)?;
            self.phase = SpoolPhase::Reading;
            Ok(())
        })
        .await
    }

    fn require_phase(&self, expected: SpoolPhase) -> Result<(), TransportError> {
        if self.phase != expected {
            return Err(TransportError::Frame(format!(
                "delta spool is {:?}, expected {expected:?}",
                self.phase
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "delta_storage_inline_tests.rs"]
mod tests;
