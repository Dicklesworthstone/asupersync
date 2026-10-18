//! Regression coverage for the existing TCP v1 emitter/validator contract.

use super::*;
use super::super::{ManifestEntry, planner_manifest_from_wire};
use crate::atp::delta::{CasChunkRef, PersistentChunkManifest};
use crate::atp::object::ContentId;
use crate::net::atp::transport_common::DeltaChunkWire;

// The planner is real. It accepts contiguous content sequences without knowing
// file boundaries; the transport must additionally validate file geometry.
fn seal(delta: &mut DeltaManifestWire) {
    let chunks = delta.chunks.iter().map(|chunk| CasChunkRef {
        index: chunk.index,
        byte_offset: chunk.stream_offset,
        size_bytes: chunk.size_bytes,
        content_id: ContentId::from_bytes(chunk.rel_path.as_bytes()),
    }).collect();
    let planner = PersistentChunkManifest::new(delta.tree_id.clone(), chunks)
        .expect("self-consistent planner layout");
    for (chunk, reference) in delta.chunks.iter_mut().zip(&planner.chunks) {
        chunk.content_id_hex = reference.content_id.to_hex();
    }
    delta.merkle_root_hex = planner.merkle_root.to_hex();
    planner_manifest_from_wire(delta).expect("real planner accepts the commitment");
}

fn fixture(lengths: &[u64], chunk_size: usize) -> (TransferManifest, DeltaManifestWire) {
    assert!(chunk_size > 0);
    let entries = lengths.iter().enumerate().map(|(index, size)| ManifestEntry {
        index: u32::try_from(index).unwrap(),
        rel_path: format!("file-{index}"),
        size: *size,
        sha256_hex: "00".repeat(32),
        metadata: None,
        members: Vec::new(),
    }).collect::<Vec<_>>();
    let mut delta = DeltaManifestWire {
        schema: super::super::ATP_DELTA_CHUNK_MANIFEST_SCHEMA.into(),
        tree_id: "33".repeat(32),
        chunk_size,
        total_size_bytes: lengths.iter().sum(),
        merkle_root_hex: String::new(),
        chunks: Vec::new(),
    };
    // A byte-slice chunk iterator is an independent way to form exact ranges.
    let mut stream_offset = 0;
    for entry in &entries {
        let bytes = vec![0_u8; usize::try_from(entry.size).unwrap()];
        let mut entry_offset = 0;
        for bytes in bytes.chunks(chunk_size) {
            let size_bytes = u64::try_from(bytes.len()).unwrap();
            delta.chunks.push(DeltaChunkWire {
                index: u32::try_from(delta.chunks.len()).unwrap(),
                entry_index: entry.index,
                rel_path: entry.rel_path.clone(),
                entry_offset,
                stream_offset,
                size_bytes,
                content_id_hex: String::new(),
            });
            entry_offset += size_bytes;
            stream_offset += size_bytes;
        }
    }
    seal(&mut delta);
    let manifest = TransferManifest {
        transfer_id: "layout".into(),
        root_name: "tree".into(),
        is_directory: true,
        total_bytes: lengths.iter().sum(),
        merkle_root_hex: delta.tree_id.clone(),
        metadata_root_hex: None,
        directory_metadata: None,
        entries,
        delta_manifest: Some(delta.clone()),
    };
    (manifest, delta)
}

#[test]
fn canonical_layout_accepts_empty_files_and_independent_final_tails() {
    for chunk_size in [1, 2, 7, 16, 4096] {
        for lengths in [vec![], vec![0, 0], vec![1, 0, 17], vec![16, 32, 33]] {
            let (manifest, delta) = fixture(&lengths, chunk_size);
            validate(&manifest, &delta).unwrap();
        }
    }
}

#[test]
fn short_nonfinal_chunks_cannot_be_hidden_by_a_valid_planner_root() {
    let (manifest, mut delta) = fixture(&[32], 16);
    delta.chunks[0].size_bytes = 8;
    delta.chunks[1].size_bytes = 24;
    delta.chunks[1].entry_offset = 8;
    delta.chunks[1].stream_offset = 8;
    seal(&mut delta);
    assert!(matches!(validate(&manifest, &delta), Err(TransportError::Frame(message))
        if message.contains("non-canonical geometry")));
}

#[test]
fn file_interleaving_cannot_be_hidden_by_contiguous_global_offsets() {
    let (manifest, mut delta) = fixture(&[32, 32], 16);
    delta.chunks.swap(1, 2);
    for (index, chunk) in delta.chunks.iter_mut().enumerate() {
        chunk.index = u32::try_from(index).unwrap();
        chunk.stream_offset = u64::try_from(index).unwrap() * 16;
    }
    // Each file's own offsets are still contiguous and every byte is covered.
    seal(&mut delta);
    assert!(matches!(validate(&manifest, &delta), Err(TransportError::Frame(message))
        if message.contains("expected chunk")));
}

#[test]
fn all_descriptor_geometry_and_entry_indices_are_checked() {
    let (manifest, delta) = fixture(&[17, 16], 16);
    for case in 0..7 {
        let mut bad = delta.clone();
        match case {
            0 => bad.chunks[0].index = 7,
            1 => bad.chunks[0].entry_index = 1,
            2 => bad.chunks[0].rel_path = "file-1".into(),
            3 => bad.chunks[0].entry_offset = 1,
            4 => bad.chunks[0].stream_offset = 1,
            5 => bad.chunks[0].size_bytes = 0,
            _ => bad.chunks[0].size_bytes = u64::MAX,
        }
        assert!(validate(&manifest, &bad).is_err(), "case {case}");
    }
    let mut bad_manifest = manifest;
    bad_manifest.entries[0].index = 1;
    assert!(validate(&bad_manifest, &delta).is_err());
}

#[test]
fn omitted_and_trailing_descriptors_are_refused() {
    let (manifest, delta) = fixture(&[17, 0], 16);
    let mut missing = delta.clone();
    missing.chunks.pop();
    assert!(validate(&manifest, &missing).is_err());
    let mut extra = delta;
    extra.chunks.push(extra.chunks[0].clone());
    assert!(validate(&manifest, &extra).is_err());
}

#[test]
fn metadata_only_entries_have_no_chunks_or_logical_stream_extent() {
    let (mut manifest, delta) = fixture(&[16, 0, 0, 1], 16);
    manifest.entries[1].metadata = Some(EntryMetadata {
        hardlink_target: Some("file-0".into()),
        ..EntryMetadata::default()
    });
    manifest.entries[2].metadata = Some(EntryMetadata {
        file_kind: FileKind::Directory,
        ..EntryMetadata::default()
    });
    validate(&manifest, &delta).unwrap();
    manifest.entries[1].size = 1;
    assert!(validate(&manifest, &delta).is_err());
}

#[test]
fn real_tcp_delta_emission_satisfies_the_stricter_layout_contract() {
    use super::super::build_delta_manifest_from_entries;
    use crate::net::atp::transport_common::SourceEntry;

    let directory = tempfile::tempdir().expect("real source files");
    let mut sources = Vec::new();
    let mut entries = Vec::new();
    let mut metadatas = Vec::new();
    let mut total_bytes = 0;
    for (index, len) in [0_usize, 1, 7, 8, 129].into_iter().enumerate() {
        let rel_path = format!("file-{index}");
        let abs_path = directory.path().join(&rel_path);
        let bytes = vec![u8::try_from(index).unwrap(); len];
        std::fs::write(&abs_path, bytes).expect("source payload");
        sources.push(SourceEntry { rel_path: rel_path.clone(), abs_path });
        let size = u64::try_from(len).unwrap();
        total_bytes += size;
        entries.push(ManifestEntry {
            index: u32::try_from(index).unwrap(),
            rel_path,
            size,
            sha256_hex: "00".repeat(32),
            metadata: None,
            members: Vec::new(),
        });
        metadatas.push(EntryMetadata::default());
    }
    let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(runtime.handle().spawn(async move {
        let root = "33".repeat(32);
        let delta = build_delta_manifest_from_entries(root.clone(), &sources, &metadatas, 7)
            .await.expect("actual TCP emitter");
        let manifest = TransferManifest {
            transfer_id: "emitter".into(),
            root_name: "tree".into(),
            is_directory: true,
            total_bytes,
            merkle_root_hex: root,
            metadata_root_hex: None,
            directory_metadata: None,
            entries,
            delta_manifest: Some(delta.clone()),
        };
        validate(&manifest, &delta).expect("accept native emitter layout");
        planner_manifest_from_wire(&delta).expect("accept native emitter root");
        for chunk in &delta.chunks {
            let source = &sources[usize::try_from(chunk.entry_index).unwrap()];
            let bytes = std::fs::read(&source.abs_path).unwrap();
            let start = usize::try_from(chunk.entry_offset).unwrap();
            let len = usize::try_from(chunk.size_bytes).unwrap();
            assert_eq!(chunk.content_id_hex, ContentId::from_bytes(&bytes[start..start + len]).to_hex());
        }
    }));
}
