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
mod tests {
    use super::*;
    use crate::net::atp::transport_common::DeltaChunkWire;
    use super::super::ManifestEntry;

    fn fixture(size: u64) -> (TransferManifest, DeltaManifestWire) {
        let entry = ManifestEntry {
            index: 0,
            rel_path: "payload".into(),
            size,
            sha256_hex: "00".repeat(32),
            metadata: None,
            members: Vec::new(),
        };
        let delta = DeltaManifestWire {
            schema: "schema".into(),
            tree_id: "tree".into(),
            chunk_size: 4096,
            total_size_bytes: size,
            merkle_root_hex: "11".repeat(32),
            chunks: if size == 0 {
                Vec::new()
            } else {
                vec![DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "payload".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: size,
                    content_id_hex: "22".repeat(32),
                }]
            },
        };
        (
            TransferManifest {
                transfer_id: "t".into(),
                root_name: "r".into(),
                is_directory: false,
                total_bytes: size,
                merkle_root_hex: "33".repeat(32),
                metadata_root_hex: None,
                directory_metadata: None,
                entries: vec![entry],
                delta_manifest: Some(delta.clone()),
            },
            delta,
        )
    }

    #[test]
    fn accepts_complete_bounded_layout() {
        let (manifest, delta) = fixture(1024);
        validate(&manifest, &delta).unwrap();
        let (manifest, delta) = fixture(0);
        validate(&manifest, &delta).unwrap();
    }

    #[test]
    fn rejects_unbounded_chunk_size_before_baseline_reads() {
        let (manifest, mut delta) = fixture(1);
        delta.chunk_size = usize::try_from(MAX_COMPRESSED_CHUNK_RAW).unwrap() + 1;
        assert!(validate(&manifest, &delta).is_err());
        delta.chunk_size = 0;
        assert!(validate(&manifest, &delta).is_err());
    }

    #[test]
    fn rejects_path_index_and_extent_mismatches() {
        let (manifest, delta) = fixture(10);
        for mutate in 0..4 {
            let mut bad = delta.clone();
            match mutate {
                0 => bad.chunks[0].entry_index = 7,
                1 => bad.chunks[0].rel_path = "other".into(),
                2 => bad.chunks[0].entry_offset = 1,
                _ => bad.chunks[0].size_bytes = 11,
            }
            assert!(validate(&manifest, &bad).is_err(), "case {mutate}");
        }
    }

    #[test]
    fn rejects_partial_coverage_and_transfer_total_mismatch() {
        let (manifest, mut delta) = fixture(10);
        delta.chunks[0].size_bytes = 9;
        assert!(validate(&manifest, &delta).is_err());

        let (manifest, mut delta) = fixture(10);
        delta.total_size_bytes = 9;
        assert!(validate(&manifest, &delta).is_err());
    }

    #[test]
    fn rejects_content_for_metadata_only_entries() {
        let (mut manifest, delta) = fixture(10);
        manifest.entries[0].metadata = Some(EntryMetadata {
            file_kind: FileKind::Directory,
            ..EntryMetadata::default()
        });
        assert!(validate(&manifest, &delta).is_err());
    }
}
