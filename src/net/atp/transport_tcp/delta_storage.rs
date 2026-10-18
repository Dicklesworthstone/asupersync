//! Payload-bounded backing storage for TCP delta reception.
//!
//! Baseline planning retains verified coverage and file ranges, not file bytes.
//! Every reused range is re-read and hash-checked before reconstruction. A path
//! changed since discovery can fail the transfer; it cannot authorize different
//! content. This is not a filesystem snapshot or a path-confinement API.

use super::{ContentId, Cx, DeltaContentKey, MAX_COMPRESSED_CHUNK_RAW, TransportError};
use crate::io::{AsyncReadExt, AsyncSeekExt};
use std::path::PathBuf;
use std::sync::Arc;

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
        cx.with_ambient(async {
            check_io(cx)?;
            let length = chunk_length(key)?;
            self.offset
                .checked_add(key.size_bytes)
                .ok_or_else(|| TransportError::Frame("delta baseline range overflows u64".into()))?;
            let source_error =
                |error| TransportError::Source(format!("{}: {error}", self.path.display()));
            let mut file = crate::fs::File::open(self.path.as_path())
                .await
                .map_err(source_error)?;
            file.seek(std::io::SeekFrom::Start(self.offset))
                .await
                .map_err(source_error)?;
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            scratch.resize(length, 0);
            file.read_exact(scratch).await.map_err(source_error)?;
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            verify_bytes(key, scratch)
        })
        .await
    }
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

pub(super) fn verify_bytes(
    key: &DeltaContentKey,
    bytes: &[u8],
) -> Result<(), TransportError> {
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
        cx.with_ambient(async {
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
        cx.with_ambient(async {
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
        cx.with_ambient(async {
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
        cx.with_ambient(async {
            check_io(cx)?;
            self.require_phase(SpoolPhase::Reading)?;
            let length = chunk_length(key)?;
            let offset = *self
                .offsets
                .get(key)
                .ok_or_else(|| TransportError::Frame("delta spool is missing the requested chunk".into()))?;
            self.phase = SpoolPhase::Failed;
            self.file.seek(std::io::SeekFrom::Start(offset)).await?;
            scratch.resize(length, 0);
            self.file.read_exact(scratch).await?;
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
