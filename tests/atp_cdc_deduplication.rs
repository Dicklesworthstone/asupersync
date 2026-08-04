//! ATP-C6 Content-Defined Chunking and Deduplication Tests.
//!
//! Comprehensive tests covering:
//! - Small edits and boundary shifts
//! - Large unchanged ranges
//! - Corrupted cached chunks
//! - Cross-transfer chunk reuse

use asupersync::atp::manifest::{ChunkMetadata, ChunkStrategy, ProofStrength};
use asupersync::net::atp::chunk::ChunkingProfile;
use asupersync::net::atp::chunk::cas::{
    CasManifestChunk, CasMerkleManifest, ChunkAddress, ContentAddressedChunkStore,
};
use asupersync::net::atp::chunk::dedupe::{CdcEngine, ChunkCache, ChunkReuseManager};
use asupersync::net::atp::chunk::dedupe::{CdcParameters, ChunkIdentity, ChunkReuseCriteria};
use asupersync::net::atp::chunk::delta_stream::DeltaChunkPayload;
use asupersync::net::atp::chunk::reassembly::{
    ReassembledFile, reassemble_from_cas_and_decoded, stage_and_commit_reassembled_tree,
    tree_digest,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::process::Command;

#[test]
fn test_cdc_small_edits_boundary_preservation() {
    let mut engine = CdcEngine::new();

    // Original content with clear structure
    let original = b"line1\nline2\nline3\nline4\nline5\n".repeat(200);

    // Small edit: change one line
    let mut modified = original.clone();
    let edit_pos = modified.windows(5).position(|w| w == b"line3").unwrap();
    modified[edit_pos..edit_pos + 5].copy_from_slice(b"LINE3");

    let params = CdcParameters {
        window_size: 32,
        min_chunk_size: 512,
        max_chunk_size: 8192,
        normalization_constant: 0x1021,
    };

    let original_chunks = engine.compute_cdc_boundaries(&original, &params).unwrap();
    let modified_chunks = engine.compute_cdc_boundaries(&modified, &params).unwrap();

    // Most chunks should remain identical (same boundaries and hashes)
    let mut unchanged_chunks = 0;
    let mut total_chunks = 0;

    // Build lookup map for original chunks by position
    let mut original_by_offset: HashMap<u64, _> = HashMap::new();
    for chunk in &original_chunks {
        original_by_offset.insert(chunk.byte_offset, chunk);
    }

    for chunk in &modified_chunks {
        total_chunks += 1;
        if let Some(original_chunk) = original_by_offset.get(&chunk.byte_offset) {
            if original_chunk.content_hash == chunk.content_hash
                && original_chunk.size_bytes == chunk.size_bytes
            {
                unchanged_chunks += 1;
            }
        }
    }

    // Expect >80% chunks to remain unchanged with small edit
    let preservation_ratio = unchanged_chunks as f64 / total_chunks as f64;
    assert!(
        preservation_ratio > 0.8,
        "Small edit should preserve most chunks, got {:.2}%",
        preservation_ratio * 100.0
    );

    println!(
        "CDC preserved {:.1}% of chunks after small edit",
        preservation_ratio * 100.0
    );
}

#[test]
fn test_cdc_boundary_shift_resilience() {
    let mut engine = CdcEngine::new();

    // Create content with repeating patterns
    let pattern = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n";
    let original = pattern.repeat(200);

    // Insert single byte at beginning to shift all positions
    let mut shifted = vec![b'X'];
    shifted.extend_from_slice(&original);

    let params = CdcParameters {
        window_size: 16,
        min_chunk_size: 256,
        max_chunk_size: 4096,
        normalization_constant: 0x9e3779b9,
    };

    let original_chunks = engine.compute_cdc_boundaries(&original, &params).unwrap();
    let shifted_chunks = engine.compute_cdc_boundaries(&shifted, &params).unwrap();

    // After re-synchronization, most content should produce same chunk hashes
    let original_hashes: std::collections::HashSet<_> =
        original_chunks.iter().map(|c| c.content_hash).collect();
    let shifted_hashes: std::collections::HashSet<_> =
        shifted_chunks.iter().map(|c| c.content_hash).collect();

    let common_hashes = original_hashes.intersection(&shifted_hashes).count();
    let resilience_ratio = common_hashes as f64 / original_hashes.len() as f64;

    // CDC should resynchronize and produce many common chunks
    assert!(
        resilience_ratio > 0.6,
        "CDC should resync after boundary shift, got {:.2}%",
        resilience_ratio * 100.0
    );

    println!(
        "CDC resynchronized {:.1}% of chunks after boundary shift",
        resilience_ratio * 100.0
    );
}

#[test]
fn test_large_unchanged_ranges() {
    let mut engine = CdcEngine::new();

    // Large file: 1MB with small changes
    let block_size = 1024;
    let num_blocks = 1024;
    let mut original = Vec::new();

    for i in 0..num_blocks {
        let block = format!("Block {:04}\n{}\n", i, "X".repeat(block_size - 20));
        original.extend_from_slice(block.as_bytes());
    }

    // Modify only a few blocks in the middle
    let mut modified = original.clone();
    for i in [100, 200, 300] {
        let block_start = i * block_size;
        let marker = format!("MODIFIED {:04}", i);
        if block_start + marker.len() < modified.len() {
            modified[block_start..block_start + marker.len()].copy_from_slice(marker.as_bytes());
        }
    }

    let params = CdcParameters {
        window_size: 64,
        min_chunk_size: 2048,
        max_chunk_size: 16384,
        normalization_constant: 0x1021,
    };

    let original_chunks = engine.compute_cdc_boundaries(&original, &params).unwrap();
    let modified_chunks = engine.compute_cdc_boundaries(&modified, &params).unwrap();

    // Count unchanged chunks by hash
    let original_hashes: std::collections::HashSet<_> =
        original_chunks.iter().map(|c| c.content_hash).collect();
    let modified_hashes: std::collections::HashSet<_> =
        modified_chunks.iter().map(|c| c.content_hash).collect();

    let unchanged_count = original_hashes.intersection(&modified_hashes).count();
    let preservation_ratio = unchanged_count as f64 / original_hashes.len() as f64;

    // Should preserve >90% of chunks with minimal changes
    assert!(
        preservation_ratio > 0.90,
        "Large unchanged ranges should be preserved, got {:.2}%",
        preservation_ratio * 100.0
    );

    println!(
        "Preserved {:.1}% of chunks in large file with small changes",
        preservation_ratio * 100.0
    );
}

#[test]
fn test_chunk_cache_operations() {
    let mut cache = ChunkCache::new(10 * 1024 * 1024); // 10MB cache

    let chunk_data = b"test chunk content for caching".to_vec();
    let identity = ChunkIdentity::from_data(&chunk_data, "test-transfer", ProofStrength::Basic);

    // Store chunk
    assert!(cache.store_chunk(&identity, &chunk_data).is_ok());

    // Retrieve chunk
    let retrieved = cache.retrieve_chunk(&identity).unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), chunk_data);

    // Test cache hit statistics
    let stats = cache.get_statistics();
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.cache_misses, 0);

    // Test non-existent chunk
    let missing_identity =
        ChunkIdentity::from_data(b"missing chunk", "test-transfer", ProofStrength::Basic);

    let missing = cache.retrieve_chunk(&missing_identity).unwrap();
    assert!(missing.is_none());

    let stats = cache.get_statistics();
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.cache_misses, 1);
}

#[test]
fn test_corrupted_cached_chunks() {
    let mut cache = ChunkCache::new(1024 * 1024);

    let original_data = b"uncorrupted chunk data".to_vec();
    let corrupted_data = b"corrupted chunk data!!".to_vec(); // Same length, different content

    let identity =
        ChunkIdentity::from_data(&original_data, "test-transfer", ProofStrength::Enhanced);

    // Store original data
    assert!(cache.store_chunk(&identity, &original_data).is_ok());

    // Public cache insertion rejects bytes whose SHA-256 does not match the
    // identity, preserving the already-stored valid chunk.
    assert!(cache.store_chunk(&identity, &corrupted_data).is_err());

    let retrieved = cache.retrieve_chunk(&identity).unwrap();
    assert_eq!(retrieved, Some(original_data));
}

#[test]
fn test_chunk_reuse_manager_cross_transfer() {
    let mut manager = ChunkReuseManager::new();

    // Simulate two transfers with overlapping content
    let transfer1_id = "transfer-001";
    let transfer2_id = "transfer-002";

    // Content that appears in both transfers
    let shared_content = b"shared content block";
    let shared_identity = manager
        .store_chunk_for_reuse(shared_content, transfer1_id)
        .unwrap();
    let shared_hash = shared_identity.content_hash;

    // Register a second transfer in the same capability scope.
    manager
        .register_transfer_chunk(transfer2_id, &shared_identity)
        .unwrap();

    // Check if chunk can be reused for second transfer
    let reuse_criteria = ChunkReuseCriteria {
        max_age_seconds: 3600,
        min_proof_strength: ProofStrength::Basic,
        require_same_algorithm: true,
    };

    let reusable = manager.find_reusable_chunks(transfer2_id, &[shared_hash], &reuse_criteria);
    assert_eq!(reusable.len(), 1);
    assert_eq!(reusable[0].content_hash, shared_hash);

    // Register the reuse
    manager
        .register_chunk_reuse(transfer2_id, &shared_identity, transfer1_id)
        .unwrap();

    // Verify reuse statistics
    let stats = manager.get_reuse_statistics(transfer2_id);
    assert!(stats.is_some());
    let stats = stats.unwrap();
    assert_eq!(stats.total_chunks_reused, 1);
    assert_eq!(stats.bytes_saved, shared_content.len() as u64);
    assert!(stats.deduplication_ratio > 0.0);
}

#[test]
fn test_reusable_chunk_query_returns_unique_content_once() {
    let mut manager = ChunkReuseManager::new();

    let transfer1_id = "transfer-unique-source";
    let transfer2_id = "transfer-unique-requester";
    let shared_content = b"shared content should be counted once";
    let shared_identity = manager
        .store_chunk_for_reuse(shared_content, transfer1_id)
        .unwrap();
    let shared_hash = shared_identity.content_hash;

    manager
        .register_transfer_chunk(transfer2_id, &shared_identity)
        .unwrap();

    let reuse_criteria = ChunkReuseCriteria {
        max_age_seconds: 3600,
        min_proof_strength: ProofStrength::Basic,
        require_same_algorithm: true,
    };

    let reusable = manager.find_reusable_chunks(
        transfer2_id,
        &[shared_hash, shared_hash, shared_hash],
        &reuse_criteria,
    );

    assert_eq!(
        reusable,
        vec![shared_identity],
        "duplicate requested content hashes must not inflate reusable chunk counts"
    );
}

#[test]
fn test_chunk_reuse_security_isolation() {
    let mut manager = ChunkReuseManager::new();

    // Two transfers with different capability scopes
    let secure_transfer = "secure-transfer";
    let public_transfer = "public-transfer";

    let secure_content = vec![7u8; 1024];
    let secure_identity = manager
        .store_chunk_for_reuse(&secure_content, secure_transfer)
        .unwrap();
    let chunk_hash = secure_identity.content_hash;

    // Public transfer should NOT be able to reuse secure chunks
    let reuse_criteria = ChunkReuseCriteria {
        max_age_seconds: 3600,
        min_proof_strength: ProofStrength::Basic,
        require_same_algorithm: true,
    };

    let reusable = manager.find_reusable_chunks(public_transfer, &[chunk_hash], &reuse_criteria);
    assert_eq!(
        reusable.len(),
        0,
        "Secure chunks should not be reusable by public transfers"
    );

    // Same capability scope should allow reuse
    let reusable = manager.find_reusable_chunks(secure_transfer, &[chunk_hash], &reuse_criteria);
    assert_eq!(
        reusable.len(),
        1,
        "Same capability scope should allow reuse"
    );
}

#[test]
fn test_cdc_deterministic_reproducibility() {
    let mut engine = CdcEngine::new();

    let test_data = b"reproducible test data for ATP-C6 verification".repeat(100);

    let params = CdcParameters {
        window_size: 32,
        min_chunk_size: 256,
        max_chunk_size: 2048,
        normalization_constant: 0x1021, // Fixed constant for determinism
    };

    // Compute boundaries multiple times
    let chunks1 = engine.compute_cdc_boundaries(&test_data, &params).unwrap();
    let chunks2 = engine.compute_cdc_boundaries(&test_data, &params).unwrap();
    let chunks3 = engine.compute_cdc_boundaries(&test_data, &params).unwrap();

    // All runs should produce identical results
    assert_eq!(chunks1.len(), chunks2.len());
    assert_eq!(chunks2.len(), chunks3.len());

    for ((c1, c2), c3) in chunks1.iter().zip(&chunks2).zip(&chunks3) {
        assert_eq!(c1.byte_offset, c2.byte_offset);
        assert_eq!(c2.byte_offset, c3.byte_offset);

        assert_eq!(c1.size_bytes, c2.size_bytes);
        assert_eq!(c2.size_bytes, c3.size_bytes);

        assert_eq!(c1.content_hash, c2.content_hash);
        assert_eq!(c2.content_hash, c3.content_hash);
    }

    println!("CDC produced {} deterministic chunks", chunks1.len());
}

#[test]
fn test_edge_cases_and_boundary_conditions() {
    let mut engine = CdcEngine::new();

    let params = CdcParameters {
        window_size: 16,
        min_chunk_size: 64,
        max_chunk_size: 512,
        normalization_constant: 0x1021,
    };

    // Empty data
    let empty_chunks = engine.compute_cdc_boundaries(&[], &params).unwrap();
    assert_eq!(empty_chunks.len(), 0);

    // Data smaller than min chunk size
    let small_data = b"tiny";
    let small_chunks = engine.compute_cdc_boundaries(small_data, &params).unwrap();
    assert_eq!(small_chunks.len(), 1);
    assert_eq!(small_chunks[0].size_bytes, small_data.len() as u64);

    // Data exactly at min chunk size
    let min_size_data = vec![b'A'; 64];
    let min_chunks = engine
        .compute_cdc_boundaries(&min_size_data, &params)
        .unwrap();
    assert_eq!(min_chunks[0].size_bytes, 64);

    // Data that would exceed max chunk size
    let large_uniform_data = vec![b'B'; 1024]; // All same byte, unlikely to find boundaries
    let large_chunks = engine
        .compute_cdc_boundaries(&large_uniform_data, &params)
        .unwrap();

    // Should respect max chunk size constraint
    for chunk in &large_chunks {
        assert!(
            chunk.size_bytes <= 512,
            "Chunk size {} exceeds maximum",
            chunk.size_bytes
        );
    }

    // Coverage verification
    let total_size: u64 = large_chunks.iter().map(|c| c.size_bytes).sum();
    assert_eq!(total_size, large_uniform_data.len() as u64);

    let mut expected_offset = 0;
    for chunk in &large_chunks {
        assert_eq!(chunk.byte_offset, expected_offset);
        expected_offset += chunk.size_bytes;
    }
}

#[test]
fn test_chunk_profile_integration() {
    let test_data = b"integration test data for chunking profile".repeat(50);

    // Test different chunking profiles
    let profiles = ChunkingProfile::ALL;

    for profile in profiles {
        let chunk_plan = profile.recommended_chunk_plan(test_data.len() as u64);

        match chunk_plan.strategy {
            ChunkStrategy::FixedSize => {
                // Fixed size chunking should create uniform chunks
                let chunk_size = chunk_plan.target_chunk_size as usize;
                let expected_chunks = (test_data.len() + chunk_size - 1) / chunk_size;
                assert!(expected_chunks > 0);
            }
            ChunkStrategy::ContentDefined => {
                // CDC should use the provided parameters
                assert!(chunk_plan.cdc_params.is_some());
                let cdc_params = chunk_plan.cdc_params.unwrap();
                assert!(cdc_params.window_size > 0);
                assert!(cdc_params.average_chunk_size > 0);
            }
            ChunkStrategy::ObjectSpecific => {
                // Object-specific profiles still produce a concrete chunk plan.
                assert!(chunk_plan.target_chunk_size > 0);
            }
        }

        // Verify profile properties
        match profile {
            ChunkingProfile::BulkFile => {
                assert!(!profile.supports_streaming());
                assert!(!profile.optimizes_for_deduplication());
                assert!(profile.provides_reproducible_chunking());
            }
            ChunkingProfile::SyncTree => {
                assert!(profile.supports_incremental_chunking());
                assert!(profile.optimizes_for_deduplication());
                assert!(!profile.supports_streaming());
            }
            ChunkingProfile::Media => {
                assert!(profile.supports_incremental_chunking());
                assert!(profile.supports_streaming());
                assert!(!profile.optimizes_for_deduplication());
            }
            ChunkingProfile::SparseImage => {
                assert!(profile.supports_sparse_data());
                assert!(!profile.supports_streaming());
                assert!(!profile.optimizes_for_deduplication());
            }
            ChunkingProfile::Artifact => {
                assert!(profile.supports_incremental_chunking());
                assert!(profile.optimizes_for_deduplication());
                assert!(profile.provides_reproducible_chunking());
            }
            ChunkingProfile::Stream => {
                assert!(profile.supports_streaming());
                // Stream may or may not optimize for deduplication
            }
        }
    }

    println!(
        "Successfully tested integration with {} chunking profiles",
        profiles.len()
    );
}

#[test]
fn toolchain_version_detection_artifact_reassembly_e2e() {
    const VERSION_PATH: &str = "metadata/rustc-vv.txt";
    const ARTIFACT_PATH: &str = "bin/current-test-exe.sample";
    const MAX_ARTIFACT_SAMPLE_BYTES: usize = 1024 * 1024;

    let rustc_output = Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()
        .expect("run the active rustc");
    assert!(
        rustc_output.status.success(),
        "rustc --version --verbose failed: {}",
        String::from_utf8_lossy(&rustc_output.stderr)
    );
    let rustc_verbose =
        String::from_utf8(rustc_output.stdout).expect("rustc version must be UTF-8");
    let version_token = rustc_verbose
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .expect("rustc version first-line token");
    let expected_toolchain = format!("rustc-{version_token}");

    let current_executable = std::env::current_exe().expect("current test executable path");
    let executable = File::open(&current_executable).expect("open current test executable");
    let mut artifact_sample = Vec::with_capacity(MAX_ARTIFACT_SAMPLE_BYTES);
    executable
        .take(u64::try_from(MAX_ARTIFACT_SAMPLE_BYTES).expect("artifact sample limit"))
        .read_to_end(&mut artifact_sample)
        .expect("read current test executable bytes");
    assert!(
        !artifact_sample.is_empty(),
        "current test executable must provide real artifact bytes"
    );
    assert!(artifact_sample.len() <= MAX_ARTIFACT_SAMPLE_BYTES);

    let inputs = [
        (
            VERSION_PATH,
            rustc_verbose.as_bytes(),
            Some(expected_toolchain.as_str()),
            true,
        ),
        (ARTIFACT_PATH, artifact_sample.as_slice(), None, false),
    ];
    let mut manifest_chunks = Vec::new();
    let mut receiver_cas = ContentAddressedChunkStore::new();
    let mut decoded_chunks = Vec::new();
    let mut decoded_addresses = BTreeSet::new();

    for (rel_path, bytes, expected_version, preload_in_cas) in inputs {
        let boundaries = ChunkingProfile::Artifact
            .compute_boundaries(bytes)
            .expect("artifact boundaries");
        let replayed_boundaries = ChunkingProfile::Artifact
            .compute_boundaries(bytes)
            .expect("replayed artifact boundaries");
        assert_eq!(boundaries, replayed_boundaries);
        assert!(
            !boundaries.is_empty(),
            "real artifact input must be chunked"
        );
        assert_eq!(
            boundaries
                .iter()
                .map(|boundary| boundary.size_bytes)
                .sum::<u64>(),
            u64::try_from(bytes.len()).expect("input size")
        );

        for boundary in boundaries {
            let Some(ChunkMetadata::Artifact { build_context, .. }) = boundary.metadata.as_ref()
            else {
                panic!("artifact boundary must carry Artifact metadata");
            };
            if let Some(expected_version) = expected_version {
                assert_eq!(build_context.toolchain_version, expected_version);
            }

            let start = usize::try_from(boundary.byte_offset).expect("chunk offset");
            let size = usize::try_from(boundary.size_bytes).expect("chunk size");
            let end = start.checked_add(size).expect("chunk end");
            let chunk_bytes = bytes.get(start..end).expect("chunk byte range");
            let address = ChunkAddress::from_bytes(chunk_bytes);
            assert_eq!(address.content_hash, boundary.content_hash);
            assert_eq!(address.size_bytes, boundary.size_bytes);

            manifest_chunks.push(CasManifestChunk {
                rel_path: rel_path.to_string(),
                byte_offset: boundary.byte_offset,
                address,
            });

            if preload_in_cas {
                let inserted = receiver_cas
                    .insert_chunk(chunk_bytes, Some(rel_path.to_string()))
                    .expect("receiver CAS insert");
                assert_eq!(inserted.address, address);
            } else if !receiver_cas.contains(&address) && decoded_addresses.insert(address) {
                decoded_chunks.push(DeltaChunkPayload::from_bytes(chunk_bytes.to_vec()));
            }
        }
    }

    let manifest = CasMerkleManifest::from_chunks("artifact-version-e2e-v1", manifest_chunks)
        .expect("artifact CAS manifest");
    let expected_cas_chunks = manifest
        .entries()
        .iter()
        .filter(|entry| receiver_cas.contains(&entry.address))
        .count();
    let expected_decoded_chunks = manifest.entries().len() - expected_cas_chunks;
    assert!(expected_cas_chunks > 0);
    assert!(expected_decoded_chunks > 0);

    let expected_files = vec![
        ReassembledFile {
            rel_path: ARTIFACT_PATH.to_string(),
            sha256: Sha256::digest(&artifact_sample).into(),
            bytes: artifact_sample.clone(),
        },
        ReassembledFile {
            rel_path: VERSION_PATH.to_string(),
            sha256: Sha256::digest(rustc_verbose.as_bytes()).into(),
            bytes: rustc_verbose.as_bytes().to_vec(),
        },
    ];
    let expected_tree_sha256 = tree_digest(&expected_files).expect("expected tree digest");

    let reassembled = reassemble_from_cas_and_decoded(
        &manifest,
        &receiver_cas,
        decoded_chunks.clone(),
        expected_tree_sha256,
    )
    .expect("artifact reassembly");

    assert_eq!(
        reassembled
            .file(ARTIFACT_PATH)
            .expect("reassembled artifact")
            .bytes
            .as_slice(),
        artifact_sample.as_slice()
    );
    assert_eq!(
        reassembled
            .file(VERSION_PATH)
            .expect("reassembled version metadata")
            .bytes
            .as_slice(),
        rustc_verbose.as_bytes()
    );
    assert_eq!(reassembled.manifest_root, manifest.root());
    assert_eq!(reassembled.tree_sha256, expected_tree_sha256);
    assert_eq!(
        reassembled.logical_bytes,
        u64::try_from(artifact_sample.len() + rustc_verbose.len()).expect("logical byte size")
    );
    assert_eq!(reassembled.cas_chunk_count(), expected_cas_chunks);
    assert_eq!(reassembled.decoded_chunk_count(), expected_decoded_chunks);

    let scratch = tempfile::tempdir().expect("artifact reassembly tempdir");
    let staging_root = scratch.path().join("staging");
    let destination_root = scratch.path().join("committed");
    let receipt = stage_and_commit_reassembled_tree(
        &manifest,
        &receiver_cas,
        decoded_chunks.clone(),
        expected_tree_sha256,
        &staging_root,
        &destination_root,
    )
    .expect("staged artifact commit");
    assert_eq!(
        receipt.committed_paths,
        vec![ARTIFACT_PATH.to_string(), VERSION_PATH.to_string()]
    );
    assert_eq!(receipt.manifest_root, manifest.root());
    assert_eq!(receipt.tree_sha256, expected_tree_sha256);
    assert_eq!(
        std::fs::read(destination_root.join(ARTIFACT_PATH)).expect("committed artifact bytes"),
        artifact_sample
    );
    assert_eq!(
        std::fs::read(destination_root.join(VERSION_PATH)).expect("committed version metadata"),
        rustc_verbose.as_bytes()
    );
    assert!(!staging_root.exists());

    let rejected_staging = scratch.path().join("rejected-staging");
    let rejected_destination = scratch.path().join("rejected-destination");
    let mut rejected_tree_sha256 = expected_tree_sha256;
    rejected_tree_sha256[0] ^= 0xff;
    let rejected = stage_and_commit_reassembled_tree(
        &manifest,
        &receiver_cas,
        decoded_chunks,
        rejected_tree_sha256,
        &rejected_staging,
        &rejected_destination,
    );
    assert!(rejected.is_err(), "wrong tree commitment must fail closed");
    assert!(!rejected_staging.exists());
    assert!(!rejected_destination.exists());
}
