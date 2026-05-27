//! Comprehensive unit tests for ATP early usability and prefix-first delivery modes.
//!
//! Tests prefix range tracking, gap rejection, invalidation after manifest mismatch,
//! cancellation, resume, sparse ranges, and consumer API invariants per ATP-E4 acceptance criteria.

use crate::atp::object::{ContentId, ObjectId};
use crate::atp::sdk::{
    DirectoryHandle, StreamEarlyUsabilityState, StreamFinalCommitState, StreamHandle,
};
use crate::atp::stream_object::{
    ByteRange, ConsumptionPolicy, EpochState, PrefixExposureDecision, PrefixExposureRecord,
    PrefixVerifiedState, StreamEpoch, StreamManifest, StreamPrefixProofArtifact, StreamProofRecord,
};
use crate::atp::sync::{
    DirectoryEarlyUsabilityPolicy, DirectoryEntryKind, DirectoryEntryMetadata,
    DirectoryFinalCommitState, DirectoryManifest, DirectoryManifestEntry, DirectoryPath,
    PathNormalizationRules,
};
use std::collections::BTreeSet;

fn test_object_id(seed: u8) -> ObjectId {
    ObjectId::content(ContentId::new([seed; 32]))
}

fn new_stream_manifest(seed: u8) -> StreamManifest {
    StreamManifest::new(test_object_id(seed))
}

fn add_epoch(stream: &mut StreamManifest, sequence: u64, start: u64, end: u64, state: EpochState) {
    stream
        .add_epoch(StreamEpoch::new(
            sequence,
            stream.object_id.clone(),
            ByteRange::new(start, end),
            state,
            vec![],
        ))
        .expect("add stream epoch");
}

fn add_file(manifest: &mut DirectoryManifest, path: &str, content_id: &str, size_bytes: u64) {
    let path = DirectoryPath::normalize(path, manifest.path_rules).expect("normalize path");
    let entry = DirectoryManifestEntry::new(
        path,
        DirectoryEntryKind::File,
        Some(content_id.to_string()),
        DirectoryEntryMetadata {
            size_bytes: Some(size_bytes),
            ..DirectoryEntryMetadata::default()
        },
    );
    manifest.insert(entry).expect("insert manifest entry");
}

/// Test verified prefix tracking with valid ranges
#[test]
fn test_verified_prefix_tracking() {
    let mut stream = new_stream_manifest(1);

    // Add verified chunks sequentially
    assert_eq!(stream.verified_prefix_end(), 0);

    stream.mark_chunk_verified(0, 64).expect("verify 0..64");
    assert_eq!(stream.verified_prefix_end(), 64);

    stream.mark_chunk_verified(64, 64).expect("verify 64..128");
    assert_eq!(stream.verified_prefix_end(), 128);

    // Gapped epochs are rejected before they can extend the prefix.
    assert!(stream.mark_chunk_verified(256, 64).is_err());
    assert_eq!(
        stream.verified_prefix_end(),
        128,
        "Gap should prevent prefix extension"
    );
}

/// Test gap rejection in prefix exposure
#[test]
fn test_gap_rejection_in_prefix() {
    let mut stream = new_stream_manifest(2);

    // Create a verified prefix and prove gapped chunks are rejected.
    stream.mark_chunk_verified(0, 100).expect("verify 0..100");
    assert!(stream.mark_chunk_verified(200, 100).is_err());
    assert!(stream.mark_chunk_verified(400, 100).is_err());

    // Prefix should only include contiguous verified range
    assert_eq!(stream.verified_prefix_end(), 100);

    // Fill first gap
    stream
        .mark_chunk_verified(100, 100)
        .expect("verify 100..200");
    stream
        .mark_chunk_verified(200, 100)
        .expect("verify 200..300");
    assert_eq!(stream.verified_prefix_end(), 300);

    // Still gap at 300-400
    assert_eq!(
        stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
        300
    );

    // Fill final gap
    stream
        .mark_chunk_verified(300, 100)
        .expect("verify 300..400");
    stream
        .mark_chunk_verified(400, 100)
        .expect("verify 400..500");
    assert_eq!(stream.verified_prefix_end(), 500);
}

/// Test prefix invalidation after manifest mismatch
#[test]
fn test_prefix_invalidation_after_manifest_mismatch() {
    let mut stream = new_stream_manifest(3);

    // Build up verified prefix
    stream.mark_chunk_verified(0, 200).expect("verify 0..200");
    stream
        .mark_chunk_verified(200, 100)
        .expect("verify 200..300");
    assert_eq!(stream.verified_prefix_end(), 300);

    // Simulate manifest mismatch that invalidates some verified content
    let invalidation_point = 200;
    stream.invalidate_from_offset(invalidation_point, "manifest hash mismatch");

    // Prefix should be truncated to safe point
    assert!(stream.verified_prefix_end() <= invalidation_point);

    // Consumer should not be able to read beyond invalidation point
    assert_eq!(
        stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
        stream.verified_prefix_end()
    );
}

/// Test cancellation preserves safe prefix state
#[test]
fn test_cancellation_preserves_prefix_state() {
    let mut stream = new_stream_manifest(4);

    // Build verified prefix
    stream.mark_chunk_verified(0, 200).expect("verify 0..200");
    let prefix_before_cancel = stream.verified_prefix_end();

    // Cancel stream
    stream.mark_cancelled("user requested cancellation");

    // Verified prefix should remain accessible for consumption
    assert_eq!(stream.verified_prefix_end(), prefix_before_cancel);
    assert_eq!(
        stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
        prefix_before_cancel
    );

    // No new chunks should be verifiable after cancellation
    assert!(
        stream.mark_chunk_verified(200, 100).is_err(),
        "Should not allow new verifications after cancellation"
    );
}

/// Test resume scenarios maintain prefix safety
#[test]
fn test_resume_maintains_prefix_safety() {
    // Original stream state
    let mut stream = new_stream_manifest(5);
    stream
        .mark_chunk_verified(0, 300)
        .expect("verify original prefix");
    let original_prefix = stream.verified_prefix_end();
    assert_eq!(original_prefix, 300);

    // Simulate resume with partial state
    let resume_point = 150;
    let mut resumed_stream = new_stream_manifest(5);

    // Resume should only expose verified content up to safe resume point
    resumed_stream
        .mark_chunk_verified(0, resume_point)
        .expect("verify resume prefix");
    assert!(resumed_stream.verified_prefix_end() <= resume_point);

    // Consumer API should enforce resume safety
    assert_eq!(
        resumed_stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
        resume_point
    );

    // Re-verification beyond resume point should be allowed
    resumed_stream
        .mark_chunk_verified(resume_point, 100)
        .expect("verify after resume point");
    assert_eq!(resumed_stream.verified_prefix_end(), resume_point + 100);
}

/// Test sparse range handling
#[test]
fn test_sparse_range_handling() {
    let mut stream = new_stream_manifest(6);

    stream.mark_chunk_verified(0, 100).expect("verify prefix");
    assert!(stream.mark_chunk_verified(500, 200).is_err());
    assert!(stream.mark_chunk_verified(1500, 300).is_err());
    assert!(stream.mark_chunk_verified(9000, 500).is_err());

    // Only contiguous prefix from start should be consumable
    assert_eq!(stream.verified_prefix_end(), 100);

    // Policy should not allow gaps to be exposed as contiguous
    let safe_end = stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly);
    assert_eq!(
        safe_end, 100,
        "Sparse ranges should not be exposed as contiguous"
    );

    // Fill gaps sequentially
    stream
        .mark_chunk_verified(100, 400)
        .expect("verify 100..500");
    stream
        .mark_chunk_verified(500, 200)
        .expect("verify 500..700");
    assert_eq!(stream.verified_prefix_end(), 700);

    stream
        .mark_chunk_verified(700, 800)
        .expect("verify 700..1500");
    stream
        .mark_chunk_verified(1500, 300)
        .expect("verify 1500..1800");
    assert_eq!(stream.verified_prefix_end(), 1800);
}

/// Test directory small file early exposure policy
#[test]
fn test_directory_small_file_early_exposure() {
    let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());

    // Add mixed file sizes
    add_file(&mut manifest, "small.txt", "content1", 50);
    add_file(&mut manifest, "medium.txt", "content2", 5000);
    add_file(&mut manifest, "large.bin", "content3", 50000);

    let verified_content = vec!["content1", "content2"]
        .into_iter()
        .map(String::from)
        .collect::<BTreeSet<_>>();

    let policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: true,
        max_small_file_bytes: 1000,
    };

    let report = manifest.early_usability_report(
        &verified_content,
        policy,
        DirectoryFinalCommitState::Pending,
        "test-replay-1",
    );

    // Small verified file should be exposed early
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.path.to_string() == "small.txt" && e.content_visible)
    );

    // Medium verified file should be withheld (above threshold)
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.path.to_string() == "medium.txt" && !e.content_visible)
    );

    // Large unverified file should be withheld
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.path.to_string() == "large.bin" && !e.content_visible)
    );

    // Safety caveat should warn about pending final commit
    assert!(
        report
            .safety_caveats
            .iter()
            .any(|c| c.contains("final directory commit not complete"))
    );
}

/// Test consumer API invariants
#[test]
fn test_consumer_api_invariants() {
    let mut stream = new_stream_manifest(7);

    // Build verified content
    stream.mark_chunk_verified(0, 400).expect("verify 0..400");

    // Consumer API should never expose unverified content as verified
    let verified_end = stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly);
    let provisional_end = stream.consumable_prefix_end(ConsumptionPolicy::AllowProvisional);

    // Verified should be subset of provisional
    assert!(verified_end <= provisional_end);

    // Multiple calls should be consistent
    assert_eq!(
        verified_end,
        stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly)
    );
    assert_eq!(
        provisional_end,
        stream.consumable_prefix_end(ConsumptionPolicy::AllowProvisional)
    );

    // API should be safe under concurrent access (within single thread test)
    for _ in 0..100 {
        assert_eq!(stream.verified_prefix_end(), 400);
    }
}

/// Test stream prefix proof artifact serialization
#[test]
fn test_stream_prefix_proof_artifact_serialization() {
    let object_id = test_object_id(9);
    let exposure = PrefixExposureRecord::new(
        object_id.clone(),
        Some(ByteRange::new(0, 1024)),
        PrefixVerifiedState::Verified,
        PrefixExposureDecision::Expose,
        ConsumptionPolicy::VerifiedOnly,
        Some("test-replay-ptr".to_string()),
    );
    let mut proof = StreamProofRecord::new(
        object_id,
        vec![42],
        2048,
        ConsumptionPolicy::VerifiedOnly,
        false,
    );
    proof.record_prefix_exposure(exposure);
    proof.sign(vec![0xde, 0xad, 0xbe, 0xef]);
    let artifact = proof.to_artifact();

    // Test serialization round-trip
    let json = serde_json::to_string(&artifact).expect("serialize artifact");
    let deserialized: StreamPrefixProofArtifact =
        serde_json::from_str(&json).expect("deserialize artifact");

    assert_eq!(artifact.schema_version, deserialized.schema_version);
    assert_eq!(
        artifact.prefix_exposures.len(),
        deserialized.prefix_exposures.len()
    );
    assert_eq!(artifact.final_offset, deserialized.final_offset);
    assert_eq!(
        artifact.consumer_signature_hex,
        deserialized.consumer_signature_hex
    );

    let original_record = &artifact.prefix_exposures[0];
    let roundtrip_record = &deserialized.prefix_exposures[0];

    assert_eq!(original_record.object_id, roundtrip_record.object_id);
    assert_eq!(original_record.prefix_range, roundtrip_record.prefix_range);
    assert_eq!(
        original_record.verified_state,
        roundtrip_record.verified_state
    );
    assert_eq!(
        original_record.consumption_policy,
        roundtrip_record.consumption_policy
    );
}

/// Test policy enforcement for large streams
#[test]
fn test_large_stream_policy_enforcement() {
    let mut stream = new_stream_manifest(8);

    // Verify initial chunks
    add_epoch(&mut stream, 1, 0, 1_000_000, EpochState::Verified);
    add_epoch(
        &mut stream,
        2,
        1_000_000,
        100_000_000,
        EpochState::Provisional,
    );

    // VerifiedOnly policy should only expose verified content
    let verified_end = stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly);
    assert_eq!(verified_end, 1_000_000);

    // AllowProvisional might expose more (depending on implementation)
    let provisional_end = stream.consumable_prefix_end(ConsumptionPolicy::AllowProvisional);
    assert!(provisional_end >= verified_end);

    // Large files should have explicit policy checks
    assert!(
        stream.requires_explicit_prefix_policy(),
        "Large streams should require explicit policy"
    );

    // Policy should prevent accidental exposure of unverified gaps
    let consumption_allowed = stream.check_consumption_policy(
        0,
        2_000_000, // Request more than verified
        ConsumptionPolicy::VerifiedOnly,
    );
    assert!(
        !consumption_allowed,
        "Should reject consumption beyond verified range"
    );
}

/// Test directory metadata exposure with final commit separation
#[test]
fn test_directory_metadata_final_commit_separation() {
    let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
    add_file(&mut manifest, "doc.md", "content1", 1000);
    add_file(&mut manifest, "config.json", "content2", 200);

    let verified = vec!["content1".to_string()]
        .into_iter()
        .collect::<BTreeSet<_>>();

    let policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: true,
        max_small_file_bytes: 500,
    };

    // Test pending state
    let pending_report = manifest.early_usability_report(
        &verified,
        policy,
        DirectoryFinalCommitState::Pending,
        "test-pending",
    );

    // Test committed state
    let committed_report = manifest.early_usability_report(
        &verified,
        policy,
        DirectoryFinalCommitState::Committed,
        "test-committed",
    );

    // Both reports should separate early usable state from final commit state
    assert!(
        pending_report
            .safety_caveats
            .iter()
            .any(|c| c.contains("final directory commit not complete"))
    );

    assert!(
        !committed_report
            .safety_caveats
            .iter()
            .any(|c| c.contains("final directory commit not complete"))
    );

    // Verified small file should be exposed in committed state
    let config_entry_committed = committed_report
        .entries
        .iter()
        .find(|e| e.path.to_string() == "config.json");
    assert!(config_entry_committed.is_some());

    // Same file should be withheld in pending if policy is strict
    let strict_policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: false,
        max_small_file_bytes: 500,
    };

    let strict_pending = manifest.early_usability_report(
        &verified,
        strict_policy,
        DirectoryFinalCommitState::Pending,
        "test-strict",
    );

    let config_entry_strict = strict_pending
        .entries
        .iter()
        .find(|e| e.path.to_string() == "config.json");
    if let Some(entry) = config_entry_strict {
        assert!(
            !entry.content_visible,
            "Strict policy should withhold content when pending"
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Integration test for directory handle early usability reporting
    #[test]
    fn test_directory_handle_early_usability_integration() {
        let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
        add_file(&mut manifest, "small.txt", "small-content", 50);
        add_file(&mut manifest, "large.bin", "large-content", 10_000);
        let mut handle = DirectoryHandle::new("integration-directory", manifest);
        handle.mark_content_verified("small-content");
        handle.mark_content_verified("large-content");

        // Test early usability report
        let report = handle.early_usability_report(
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            "integration-test-replay",
        );

        assert!(
            !report.metadata_paths.is_empty(),
            "Should have metadata paths"
        );
        assert!(
            report.replay_pointer.contains("integration-test"),
            "Should include replay pointer"
        );
    }

    /// Integration test for stream handle prefix consumption
    #[test]
    fn test_stream_handle_prefix_consumption_integration() {
        let mut manifest = new_stream_manifest(10);

        // Build verified prefix
        add_epoch(&mut manifest, 1, 0, 1000, EpochState::Verified);
        add_epoch(&mut manifest, 2, 1000, 2000, EpochState::Verified);

        let handle = StreamHandle {
            stream_id: "test-stream".to_string(),
            total_bytes: 10_000,
            bytes_sent: 2_000,
            manifest: Some(manifest),
        };

        // Test prefix consumption
        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);
        let verified_end = report.verified_prefix_end;
        assert_eq!(verified_end, 2000, "Should have 2KB verified prefix");

        // Test consumption policy enforcement
        let can_consume_verified = report.policy_exposed_prefix == Some(ByteRange::new(0, 2000));
        assert!(
            can_consume_verified,
            "Should allow consumption of verified range"
        );

        let can_consume_beyond = report.policy_prefix_end >= 3000;
        assert!(
            !can_consume_beyond,
            "Should reject consumption beyond verified range"
        );
    }
}
