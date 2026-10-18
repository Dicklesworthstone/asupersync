//! Fail-closed structural validation for receiver-controlled delta manifests.
//!
//! This runs before receiver baseline discovery so attacker-controlled chunk
//! geometry cannot drive large scratch allocations or path reads first.

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
    if delta.chunk_size == 0
        || u64::try_from(delta.chunk_size).unwrap_or(u64::MAX) > u64::from(MAX_COMPRESSED_CHUNK_RAW)
    {
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

    let mut next_offsets = vec![0u64; manifest.entries.len()];
    for chunk in &delta.chunks {
        if chunk.size_bytes == 0 || chunk.size_bytes > u64::from(MAX_COMPRESSED_CHUNK_RAW) {
            return Err(TransportError::Frame(format!(
                "delta chunk {} has invalid size {}",
                chunk.index, chunk.size_bytes
            )));
        }
        let entry_index = usize::try_from(chunk.entry_index)
            .map_err(|_| TransportError::Frame("delta entry index exceeds usize::MAX".into()))?;
        let entry = manifest.entries.get(entry_index).ok_or_else(|| {
            TransportError::Frame(format!(
                "delta chunk {} names unknown entry {}",
                chunk.index, chunk.entry_index
            ))
        })?;
        if chunk.rel_path != entry.rel_path {
            return Err(TransportError::Frame(format!(
                "delta chunk {} path {} does not match entry {}",
                chunk.index, chunk.rel_path, entry.rel_path
            )));
        }
        let default_metadata = EntryMetadata::default();
        let metadata = entry.metadata.as_ref().unwrap_or(&default_metadata);
        if !matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some() {
            return Err(TransportError::Frame(format!(
                "delta chunk {} targets metadata-only entry {}",
                chunk.index, entry.rel_path
            )));
        }
        let expected = next_offsets[entry_index];
        if chunk.entry_offset != expected {
            return Err(TransportError::Frame(format!(
                "delta chunk {} for {} starts at {}, expected {}",
                chunk.index, entry.rel_path, chunk.entry_offset, expected
            )));
        }
        let end = chunk.entry_offset.checked_add(chunk.size_bytes).ok_or_else(|| {
            TransportError::Frame(format!("delta chunk {} entry range overflows u64", chunk.index))
        })?;
        if end > entry.size {
            return Err(TransportError::Frame(format!(
                "delta chunk {} overruns entry {} size {}",
                chunk.index, entry.rel_path, entry.size
            )));
        }
        next_offsets[entry_index] = end;
    }

    for (entry_index, entry) in manifest.entries.iter().enumerate() {
        let default_metadata = EntryMetadata::default();
        let metadata = entry.metadata.as_ref().unwrap_or(&default_metadata);
        let carries_content =
            matches!(metadata.file_kind, FileKind::Regular) && metadata.hardlink_target.is_none();
        let observed = next_offsets[entry_index];
        if carries_content {
            if observed != entry.size {
                return Err(TransportError::Frame(format!(
                    "delta manifest covers {observed} of {} bytes for {}",
                    entry.size, entry.rel_path
                )));
            }
        } else if observed != 0 {
            return Err(TransportError::Frame(format!(
                "delta manifest carries content for metadata-only entry {}",
                entry.rel_path
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "delta_manifest_validation_inline_tests.rs"]
mod tests;
