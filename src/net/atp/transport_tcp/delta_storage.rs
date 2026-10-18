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
