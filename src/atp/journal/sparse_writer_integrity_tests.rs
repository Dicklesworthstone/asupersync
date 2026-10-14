//! Real file verification must authenticate the complete selected object.

use super::*;
use crate::atp::manifest::ChunkStrategy;
use crate::atp::object::{ContentId, ManifestId, MetadataPolicy, Object, ObjectGraph};
use futures_lite::future::block_on;
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "asupersync_sparse_integrity_{}_{}_{}",
        std::process::id(),
        nanos,
        NEXT.fetch_add(1, Ordering::Relaxed),
    ))
}

fn refresh_root(manifest: &mut Manifest) {
    manifest.merkle_root = MerkleRoot::from_manifest_components(
        &manifest.objects,
        &manifest.chunk_plan,
        &manifest.raptorq_layout,
        &manifest.compression_policy,
        &manifest.encryption_policy,
        &manifest.capability_policy,
        &manifest.transform_order,
        &manifest.transform_proof_policy,
        &manifest.repair_groups,
    );
    // Negative writer tests must not accidentally pass because the manifest
    // itself has a bad root or another unrelated structural error.
    manifest.validate().unwrap();
}

fn descriptors(content: &[u8], ranges: &[(usize, usize)]) -> Vec<ChunkBoundary> {
    ranges.iter().enumerate().map(|(index, &(start, end))| ChunkBoundary {
        index: u32::try_from(index).unwrap(),
        byte_offset: start as u64,
        size_bytes: (end - start) as u64,
        content_hash: Sha256::digest(&content[start..end]).into(),
        strategy: ChunkStrategy::FixedSize,
        metadata: None,
    }).collect()
}

fn manifest_for(
    content: &[u8],
    content_addressed: bool,
    whole_hash: bool,
    ranges: &[(usize, usize)],
) -> (ObjectId, Manifest) {
    let object = Object::file(content.to_vec());
    let old_id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
    let id = if content_addressed {
        old_id.clone()
    } else {
        ObjectId::manifest(ManifestId::from_manifest_bytes(b"writer-integrity-test-object"))
    };
    let mut record = manifest.objects.remove(&old_id).unwrap();
    record.id = id.clone();
    record.content_hash = whole_hash.then(|| {
        if content_addressed {
            *ContentId::from_bytes(content).hash()
        } else {
            Sha256::digest(content).into()
        }
    });
    record.chunk_boundaries = descriptors(content, ranges);
    manifest.objects.insert(id.clone(), record);
    manifest.roots = vec![id.clone()];
    refresh_root(&mut manifest);
    (id, manifest)
}

fn write_local(
    object_id: ObjectId,
    bytes: &[u8],
    commit_policy: CommitPolicy,
) -> (Cx, SparseWriter, PathBuf) {
    let cx = Cx::for_testing();
    let destination = unique_path();
    let writer = block_on(SparseWriter::new(
        &cx,
        object_id,
        &destination,
        SparseWriterConfig {
            enable_preallocation: false,
            commit_policy,
            ..SparseWriterConfig::default()
        },
    )).unwrap();
    writer.set_expected_size(bytes.len() as u64).unwrap();
    if !bytes.is_empty() {
        block_on(writer.write_chunk(&cx, 0, bytes, WriteOptions::default())).unwrap();
    }
    (cx, writer, destination)
}

fn assert_not_publishable(cx: &Cx, writer: &SparseWriter, destination: &Path) {
    assert!(matches!(writer.get_stats().verification_state, VerificationState::Failed { .. }));
    assert!(matches!(block_on(writer.commit(cx)), Outcome::Err(SparseWriterError::NotVerified)));
    assert!(!destination.exists());
}

fn assert_refused(cx: &Cx, writer: &SparseWriter, manifest: &Manifest, destination: &Path) {
    assert!(matches!(block_on(writer.verify(cx, manifest)),
        Outcome::Err(SparseWriterError::VerificationFailed(_))));
    assert_not_publishable(cx, writer, destination);
}

fn assert_pinned_refused(
    cx: &Cx,
    writer: &SparseWriter,
    manifest: &Manifest,
    expected: &ManifestChunkCommitment,
    destination: &Path,
) {
    assert!(matches!(block_on(writer.verify_with_chunk_commitment(cx, manifest, expected)),
        Outcome::Err(SparseWriterError::VerificationFailed(_))));
    assert_not_publishable(cx, writer, destination);
}

#[test]
fn legacy_root_alone_cannot_authorize_even_a_complete_chunk_only_file() {
    let content = b"abcdefgh";
    let (id, manifest) = manifest_for(content, false, false, &[(0, 4), (4, 8)]);
    let (cx, writer, destination) = write_local(id, content, CommitPolicy::AtomicRename);
    assert!(writer.is_complete());
    assert_refused(&cx, &writer, &manifest, &destination);
    // A refusal does not poison the staging bytes: explicit authority can retry.
    let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
    block_on(writer.verify_with_chunk_commitment(&cx, &manifest, &expected)).unwrap();
    assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
    assert_eq!(std::fs::read(destination).unwrap(), content);
}

#[test]
fn pinned_chunk_only_manifests_cannot_leave_holes_or_unchecked_suffixes() {
    let content = b"abcdefgh";
    let cases: &[&[(usize, usize)]] = &[
        &[(2, 8)],
        &[(0, 3), (4, 8)],
        &[(0, 6)],
        &[(0, 0), (0, 8)],
        &[],
    ];
    for ranges in cases {
        let (id, manifest) = manifest_for(content, false, false, ranges);
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        let (cx, writer, destination) = write_local(id, content, CommitPolicy::AtomicRename);
        assert!(writer.is_complete());
        assert_pinned_refused(&cx, &writer, &manifest, &expected, &destination);
    }
}

#[test]
fn pinned_complete_chunks_detect_corruption_at_every_byte() {
    let content = b"abcdefgh";
    for offset in 0..content.len() {
        let (id, manifest) = manifest_for(content, false, false, &[(0, 3), (3, 5), (5, 8)]);
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        let mut corrupted = *content;
        corrupted[offset] ^= 1;
        // Local write hashes correctly describe the corrupted local bytes.
        let (cx, writer, destination) = write_local(id, &corrupted, CommitPolicy::AtomicRename);
        assert_pinned_refused(&cx, &writer, &manifest, &expected, &destination);
    }
}

#[test]
fn pinned_complete_files_commit_under_every_publication_policy() {
    let content = b"abcdefgh";
    for content_addressed in [false, true] {
        for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
            let (id, manifest) = manifest_for(content, content_addressed, false, &[(0, 3), (3, 8)]);
            let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
            let (cx, writer, destination) = write_local(id, content, policy);
            block_on(writer.verify_with_chunk_commitment(&cx, &manifest, &expected)).unwrap();
            assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
            assert_eq!(std::fs::read(destination).unwrap(), content);
        }
    }
}

#[test]
fn a_manifest_cannot_substitute_bytes_for_a_selected_content_addressed_key() {
    let expected = b"expected";
    let substituted = b"tampered";
    assert_eq!(expected.len(), substituted.len());
    for whole_hash in [false, true] {
        let (id, mut manifest) = manifest_for(expected, true, whole_hash, &[(0, 8)]);
        let record = manifest.objects.get_mut(&id).unwrap();
        record.chunk_boundaries = descriptors(substituted, &[(0, 8)]);
        record.content_hash = whole_hash.then(|| *ContentId::from_bytes(substituted).hash());
        refresh_root(&mut manifest);
        let (cx, writer, destination) = write_local(id, substituted, CommitPolicy::AtomicRename);
        assert_refused(&cx, &writer, &manifest, &destination);
    }
}

#[test]
fn manifest_record_identity_must_match_the_selected_map_key() {
    let content = b"abcdefgh";
    let (id, mut manifest) = manifest_for(content, true, true, &[]);
    manifest.objects.get_mut(&id).unwrap().id = ObjectId::content(ContentId::from_bytes(b"other"));
    refresh_root(&mut manifest);
    let (cx, writer, destination) = write_local(id, content, CommitPolicy::AtomicRename);
    assert_refused(&cx, &writer, &manifest, &destination);
}

#[test]
fn partial_chunk_hints_remain_valid_with_a_whole_object_hash() {
    let content = b"abcdefgh";
    for content_addressed in [false, true] {
        let (id, manifest) = manifest_for(content, content_addressed, true, &[(2, 5)]);
        let (cx, writer, destination) = write_local(id, content, CommitPolicy::AtomicRename);
        block_on(writer.verify(&cx, &manifest)).unwrap();
        assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
        assert_eq!(std::fs::read(destination).unwrap(), content);
    }
}

#[test]
fn chunk_coverage_rejects_overflow_extra_bytes_and_zero_length_descriptors() {
    let mut chunks = vec![ChunkBoundary {
        index: 0,
        byte_offset: 0,
        size_bytes: u64::MAX,
        content_hash: [0; 32],
        strategy: ChunkStrategy::FixedSize,
        metadata: None,
    }];
    assert!(SparseWriter::require_complete_manifest_chunks(&chunks, u64::MAX).is_ok());
    assert!(SparseWriter::require_complete_manifest_chunks(&chunks, 8).is_err());
    chunks.push(ChunkBoundary {
        index: 1,
        byte_offset: u64::MAX,
        size_bytes: 1,
        content_hash: [0; 32],
        strategy: ChunkStrategy::FixedSize,
        metadata: None,
    });
    assert!(SparseWriter::require_complete_manifest_chunks(&chunks, u64::MAX).is_err());
    assert!(SparseWriter::require_complete_manifest_chunks(&[], 0).is_ok());
    assert!(SparseWriter::require_complete_manifest_chunks(&[], 1).is_err());
    chunks.truncate(1);
    chunks[0].size_bytes = 0;
    assert!(SparseWriter::require_complete_manifest_chunks(&chunks, 0).is_err());
}

#[test]
fn a_forged_chunk_ledger_cannot_reuse_the_trusted_commitment_or_downgrade() {
    let (id, mut manifest) = manifest_for(b"abcdefgh", false, false, &[(0, 8)]);
    let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
    let root = manifest.merkle_root.clone();
    manifest.objects.get_mut(&id).unwrap().chunk_boundaries = descriptors(b"tampered", &[(0, 8)]);
    manifest.validate().unwrap();
    assert_eq!(manifest.merkle_root, root);
    let (cx, writer, destination) = write_local(id, b"tampered", CommitPolicy::AtomicRename);
    assert_pinned_refused(&cx, &writer, &manifest, &expected, &destination);
    assert_refused(&cx, &writer, &manifest, &destination);
}

#[test]
fn a_wrong_pin_invalidates_prior_verification_and_refuses_empty_staging() {
    let wrong = ManifestChunkCommitment::new([0; 32]);
    for content in [b"data".as_slice(), b"".as_slice()] {
        let (id, manifest) = manifest_for(content, true, true, &[]);
        let (cx, writer, destination) = write_local(id, content, CommitPolicy::AtomicRename);
        if content.is_empty() {
            assert!(writer.lock_state().temp_file.is_none());
            assert_pinned_refused(&cx, &writer, &manifest, &wrong, &destination);
            assert!(writer.lock_state().temp_file.is_none());
        }
        block_on(writer.verify(&cx, &manifest)).unwrap();
        assert!(matches!(writer.get_stats().verification_state, VerificationState::Verified { .. }));
        assert_pinned_refused(&cx, &writer, &manifest, &wrong, &destination);
    }
}

#[test]
fn empty_manifest_addressed_files_need_a_pin_and_then_commit_normally() {
    for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
        let (id, manifest) = manifest_for(b"", false, false, &[]);
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        let (cx, writer, destination) = write_local(id, b"", policy);
        assert_refused(&cx, &writer, &manifest, &destination);
        block_on(writer.verify_with_chunk_commitment(&cx, &manifest, &expected)).unwrap();
        assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
        assert!(std::fs::read(destination).unwrap().is_empty());
    }
}

#[test]
fn selected_content_ids_authenticate_without_redundant_manifest_hashes() {
    for content in [b"data".as_slice(), b"".as_slice()] {
        let (id, manifest) = manifest_for(content, true, false, &[]);
        let (cx, writer, destination) = write_local(id, content, CommitPolicy::AtomicRename);
        block_on(writer.verify(&cx, &manifest)).unwrap();
        assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
        assert_eq!(std::fs::read(destination).unwrap(), content);
    }
}
