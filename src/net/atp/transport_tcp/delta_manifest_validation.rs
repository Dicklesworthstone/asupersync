//! Bind the TCP delta plan to the transfer and its canonical fixed-size layout.
//!
//! This runs before receiver baseline discovery. The ordered walk needs no
//! per-entry offset allocation and rejects malformed geometry before it can
//! choose receiver source reads, scratch allocation, or a no-op transfer.

use super::{
    DeltaManifestWire, EntryMetadata, FileKind, MAX_COMPRESSED_CHUNK_RAW, TransferManifest,
    TransportError,
};

pub(super) fn validate(
    manifest: &TransferManifest,
    delta: &DeltaManifestWire,
) -> Result<(), TransportError> {
    // The planner commits to tree_id, not to the enclosing transfer's root.
    // Native TCP senders use the content root as tree_id. Without this binding,
    // a valid old delta plan can select AlreadyInSync for different new content.
    if delta.tree_id != manifest.merkle_root_hex {
        return Err(TransportError::Frame(
            "delta manifest tree id does not match transfer content root".into(),
        ));
    }
    let chunk_size = u64::try_from(delta.chunk_size).unwrap_or(u64::MAX);
    if chunk_size == 0 || chunk_size > u64::from(MAX_COMPRESSED_CHUNK_RAW) {
        return Err(TransportError::Frame(format!(
            "delta manifest chunk_size {} exceeds bounded source-read limit {}",
            delta.chunk_size, MAX_COMPRESSED_CHUNK_RAW
        )));
    }
    if delta.total_size_bytes != manifest.total_bytes {
        return Err(TransportError::Frame(format!(
            "delta manifest total size {} does not match transfer total {}",
            delta.total_size_bytes, manifest.total_bytes
        )));
    }

    let default_metadata = EntryMetadata::default();
    let mut chunks = delta.chunks.iter().enumerate();
    let mut stream_offset = 0_u64;
    for (entry_position, entry) in manifest.entries.iter().enumerate() {
        let entry_index = u32::try_from(entry_position)
            .map_err(|_| TransportError::Frame("delta entry index exceeds u32::MAX".into()))?;
        if entry.index != entry_index {
            return Err(TransportError::Frame(format!(
                "delta entry index {} does not match position {entry_position}",
                entry.index
            )));
        }
        let metadata = entry.metadata.as_ref().unwrap_or(&default_metadata);
        let carries_content =
            matches!(metadata.file_kind, FileKind::Regular) && metadata.hardlink_target.is_none();
        if !carries_content {
            if entry.size != 0 {
                return Err(TransportError::Frame(format!(
                    "delta metadata-only entry {} declares content bytes",
                    entry.rel_path
                )));
            }
            continue;
        }

        let mut entry_offset = 0_u64;
        while entry_offset < entry.size {
            let Some((chunk_position, chunk)) = chunks.next() else {
                return Err(TransportError::Frame(format!(
                    "delta manifest covers {entry_offset} of {} bytes for {}",
                    entry.size, entry.rel_path
                )));
            };
            let chunk_index = u32::try_from(chunk_position)
                .map_err(|_| TransportError::Frame("delta chunk index exceeds u32::MAX".into()))?;
            if chunk.index != chunk_index || chunk.entry_index != entry_index {
                return Err(TransportError::Frame(format!(
                    "delta chunk {} targets entry {}, expected chunk {chunk_index} of entry {entry_index}",
                    chunk.index, chunk.entry_index
                )));
            }
            if chunk.rel_path != entry.rel_path {
                return Err(TransportError::Frame(format!(
                    "delta chunk {} path {} does not match entry {}",
                    chunk.index, chunk.rel_path, entry.rel_path
                )));
            }
            // v1 emitters finish each file before starting the next. Every
            // non-final chunk is exactly chunk_size, even after a short read.
            // A future CDC layout needs negotiation, not silent v1 acceptance.
            let expected_size = chunk_size.min(entry.size - entry_offset);
            if chunk.entry_offset != entry_offset
                || chunk.stream_offset != stream_offset
                || chunk.size_bytes != expected_size
            {
                return Err(TransportError::Frame(format!(
                    "delta chunk {} has non-canonical geometry for {}: expected entry offset {entry_offset}, stream offset {stream_offset}, size {expected_size}",
                    chunk.index, entry.rel_path
                )));
            }
            entry_offset = entry_offset.checked_add(expected_size).ok_or_else(|| {
                TransportError::Frame("delta entry range overflows u64".into())
            })?;
            stream_offset = stream_offset.checked_add(expected_size).ok_or_else(|| {
                TransportError::Frame("delta stream range overflows u64".into())
            })?;
        }
    }
    if chunks.next().is_some() {
        return Err(TransportError::Frame(
            "delta manifest contains chunks beyond the transfer entries".into(),
        ));
    }
    if stream_offset != delta.total_size_bytes {
        return Err(TransportError::Frame(format!(
            "delta manifest covers {stream_offset} bytes, expected {}",
            delta.total_size_bytes
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "delta_manifest_validation_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "delta_layout_tests.rs"]
mod layout_tests;
