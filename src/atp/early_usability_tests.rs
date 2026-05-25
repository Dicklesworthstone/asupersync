//! Comprehensive unit tests for ATP early usability and prefix-first delivery modes.
//!
//! Tests prefix range tracking, gap rejection, invalidation after manifest mismatch,
//! cancellation, resume, sparse ranges, and consumer API invariants per ATP-E4 acceptance criteria.

use crate::atp::stream_object::{
    ConsumptionPolicy, StreamObject, StreamPrefixProofArtifact, StreamPrefixRecord,
};
use crate::atp::sync::{
    DirectoryEarlyUsabilityPolicy, DirectoryFinalCommitState, DirectoryManifest, DirectoryPath,
};
use crate::atp::sdk::{DirectoryHandle, StreamHandle};
use crate::types::{Time, TraceId};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

/// Test verified prefix tracking with valid ranges
#[test]
fn test_verified_prefix_tracking() {
    let mut stream = StreamObject::new("test-stream", 1024);

    // Add verified chunks sequentially
    assert_eq!(stream.verified_prefix_end(), 0);

    stream.mark_chunk_verified(0, 64);
    assert_eq!(stream.verified_prefix_end(), 64);

    stream.mark_chunk_verified(64, 64);
    assert_eq!(stream.verified_prefix_end(), 128);

    // Gap should stop prefix growth
    stream.mark_chunk_verified(256, 64);
    assert_eq!(stream.verified_prefix_end(), 128, "Gap should prevent prefix extension");
}

/// Test gap rejection in prefix exposure
#[test]
fn test_gap_rejection_in_prefix() {
    let mut stream = StreamObject::new("test-stream", 1000);

    // Create verified chunks with gaps
    stream.mark_chunk_verified(0, 100);   // 0-100
    stream.mark_chunk_verified(200, 100); // 200-300 (gap 100-200)
    stream.mark_chunk_verified(400, 100); // 400-500 (gap 300-400)

    // Prefix should only include contiguous verified range
    assert_eq!(stream.verified_prefix_end(), 100);

    // Fill first gap
    stream.mark_chunk_verified(100, 100);
    assert_eq!(stream.verified_prefix_end(), 300);

    // Still gap at 300-400
    assert_eq!(stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly), 300);

    // Fill final gap
    stream.mark_chunk_verified(300, 100);
    assert_eq!(stream.verified_prefix_end(), 500);
}

/// Test prefix invalidation after manifest mismatch
#[test]
fn test_prefix_invalidation_after_manifest_mismatch() {
    let mut stream = StreamObject::new("test-stream", 1000);

    // Build up verified prefix
    stream.mark_chunk_verified(0, 300);
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
    let mut stream = StreamObject::new("test-stream", 1000);

    // Build verified prefix
    stream.mark_chunk_verified(0, 200);
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
    let result = std::panic::catch_unwind(|| {
        stream.mark_chunk_verified(200, 100);
    });
    assert!(result.is_err(), "Should not allow new verifications after cancellation");
}

/// Test resume scenarios maintain prefix safety
#[test]
fn test_resume_maintains_prefix_safety() {
    // Original stream state
    let mut stream = StreamObject::new("test-stream", 1000);
    stream.mark_chunk_verified(0, 300);
    let original_prefix = stream.verified_prefix_end();

    // Simulate resume with partial state
    let resume_point = 150;
    let mut resumed_stream = StreamObject::new("test-stream", 1000);

    // Resume should only expose verified content up to safe resume point
    resumed_stream.mark_chunk_verified(0, resume_point);
    assert!(resumed_stream.verified_prefix_end() <= resume_point);

    // Consumer API should enforce resume safety
    assert_eq!(
        resumed_stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
        resume_point
    );

    // Re-verification beyond resume point should be allowed
    resumed_stream.mark_chunk_verified(resume_point, 100);
    assert_eq!(resumed_stream.verified_prefix_end(), resume_point + 100);
}

/// Test sparse range handling
#[test]
fn test_sparse_range_handling() {
    let mut stream = StreamObject::new("test-stream", 10000);

    // Create sparse verified ranges
    let ranges = vec![
        (0, 100),       // Start
        (500, 200),     // Middle gap
        (1500, 300),    // Larger gap
        (9000, 500),    // Near end
    ];

    for (offset, size) in ranges {
        stream.mark_chunk_verified(offset, size);
    }

    // Only contiguous prefix from start should be consumable
    assert_eq!(stream.verified_prefix_end(), 100);

    // Policy should not allow gaps to be exposed as contiguous
    let safe_end = stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly);
    assert_eq!(safe_end, 100, "Sparse ranges should not be exposed as contiguous");

    // Fill gaps sequentially
    stream.mark_chunk_verified(100, 400); // Fill to connect with 500-700
    assert_eq!(stream.verified_prefix_end(), 700);

    stream.mark_chunk_verified(700, 800); // Fill to connect with 1500-1800
    assert_eq!(stream.verified_prefix_end(), 1800);
}

/// Test directory small file early exposure policy
#[test]
fn test_directory_small_file_early_exposure() {
    let mut manifest = DirectoryManifest::new();

    // Add mixed file sizes
    manifest.add_file("small.txt", "content1", Some(50)).unwrap();
    manifest.add_file("medium.txt", "content2", Some(5000)).unwrap();
    manifest.add_file("large.bin", "content3", Some(50000)).unwrap();

    let verified_content = vec!["content1", "content2"].into_iter()
        .map(String::from).collect::<BTreeSet<_>>();

    let policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: true,
        small_file_threshold_bytes: 1000,
        expose_small_files_early: true,
    };

    let report = manifest.early_usability_report(
        &verified_content,
        policy,
        DirectoryFinalCommitState::Pending,
        "test-replay-1",
    );

    // Small verified file should be exposed early
    assert!(report.entries.iter().any(|e|
        e.path.to_string() == "small.txt" && e.content_visible
    ));

    // Medium verified file should be withheld (above threshold)
    assert!(report.entries.iter().any(|e|
        e.path.to_string() == "medium.txt" && !e.content_visible
    ));

    // Large unverified file should be withheld
    assert!(report.entries.iter().any(|e|
        e.path.to_string() == "large.bin" && !e.content_visible
    ));

    // Safety caveat should warn about pending final commit
    assert!(report.safety_caveats.iter().any(|c|
        c.contains("final directory commit not complete")
    ));
}

/// Test consumer API invariants
#[test]
fn test_consumer_api_invariants() {
    let mut stream = StreamObject::new("test-stream", 1000);

    // Build verified content
    stream.mark_chunk_verified(0, 400);

    // Consumer API should never expose unverified content as verified
    let verified_end = stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly);
    let provisional_end = stream.consumable_prefix_end(ConsumptionPolicy::AllowProvisional);

    // Verified should be subset of provisional
    assert!(verified_end <= provisional_end);

    // Multiple calls should be consistent
    assert_eq!(verified_end, stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly));
    assert_eq!(provisional_end, stream.consumable_prefix_end(ConsumptionPolicy::AllowProvisional));

    // API should be safe under concurrent access (within single thread test)
    for _ in 0..100 {
        assert_eq!(stream.verified_prefix_end(), 400);
    }
}

/// Test stream prefix proof artifact serialization
#[test]
fn test_stream_prefix_proof_artifact_serialization() {
    let record = StreamPrefixRecord {
        object_id: "test-object".to_string(),
        object_hash: "abc123".to_string(),
        prefix_start: 0,
        prefix_end: 1024,
        verified: true,
        exposed_to_consumer: true,
        invalidation_reason: None,
        exposure_decision: "verified content within policy".to_string(),
        replay_pointer: "test-replay-ptr".to_string(),
        policy: ConsumptionPolicy::VerifiedOnly,
        timestamp: Time::now(),
        epoch: 42,
    };

    let artifact = StreamPrefixProofArtifact {
        schema_version: "asupersync.atp.stream-prefix-proof.v1".to_string(),
        records: vec![record.clone()],
        final_offset: Some(2048),
        signature_hex: Some("deadbeef".to_string()),
    };

    // Test serialization round-trip
    let json = serde_json::to_string(&artifact).expect("serialize artifact");
    let deserialized: StreamPrefixProofArtifact = serde_json::from_str(&json)
        .expect("deserialize artifact");

    assert_eq!(artifact.schema_version, deserialized.schema_version);
    assert_eq!(artifact.records.len(), deserialized.records.len());
    assert_eq!(artifact.final_offset, deserialized.final_offset);

    let original_record = &artifact.records[0];
    let roundtrip_record = &deserialized.records[0];

    assert_eq!(original_record.object_id, roundtrip_record.object_id);
    assert_eq!(original_record.prefix_start, roundtrip_record.prefix_start);
    assert_eq!(original_record.prefix_end, roundtrip_record.prefix_end);
    assert_eq!(original_record.verified, roundtrip_record.verified);
    assert_eq!(original_record.policy, roundtrip_record.policy);
}

/// Test policy enforcement for large streams
#[test]
fn test_large_stream_policy_enforcement() {
    let mut stream = StreamObject::new("large-media-file", 100_000_000); // 100MB

    // Verify initial chunks
    stream.mark_chunk_verified(0, 1_000_000); // 1MB verified

    // VerifiedOnly policy should only expose verified content
    let verified_end = stream.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly);
    assert_eq!(verified_end, 1_000_000);

    // AllowProvisional might expose more (depending on implementation)
    let provisional_end = stream.consumable_prefix_end(ConsumptionPolicy::AllowProvisional);
    assert!(provisional_end >= verified_end);

    // Large files should have explicit policy checks
    assert!(stream.requires_explicit_prefix_policy(),
        "Large streams should require explicit policy");

    // Policy should prevent accidental exposure of unverified gaps
    let consumption_allowed = stream.check_consumption_policy(
        0,
        2_000_000, // Request more than verified
        ConsumptionPolicy::VerifiedOnly
    );
    assert!(!consumption_allowed, "Should reject consumption beyond verified range");
}

/// Test directory metadata exposure with final commit separation
#[test]
fn test_directory_metadata_final_commit_separation() {
    let mut manifest = DirectoryManifest::new();
    manifest.add_file("doc.md", "content1", Some(1000)).unwrap();
    manifest.add_file("config.json", "content2", Some(200)).unwrap();

    let verified = vec!["content1".to_string()].into_iter().collect::<BTreeSet<_>>();

    let policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: true,
        small_file_threshold_bytes: 500,
        expose_small_files_early: true,
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
    assert!(pending_report.safety_caveats.iter().any(|c|
        c.contains("final directory commit not complete")
    ));

    assert!(!committed_report.safety_caveats.iter().any(|c|
        c.contains("final directory commit not complete")
    ));

    // Verified small file should be exposed in committed state
    let config_entry_committed = committed_report.entries.iter()
        .find(|e| e.path.to_string() == "config.json");
    assert!(config_entry_committed.is_some());

    // Same file should be withheld in pending if policy is strict
    let strict_policy = DirectoryEarlyUsabilityPolicy {
        expose_metadata_before_final: false,
        small_file_threshold_bytes: 500,
        expose_small_files_early: false,
    };

    let strict_pending = manifest.early_usability_report(
        &verified,
        strict_policy,
        DirectoryFinalCommitState::Pending,
        "test-strict",
    );

    let config_entry_strict = strict_pending.entries.iter()
        .find(|e| e.path.to_string() == "config.json");
    if let Some(entry) = config_entry_strict {
        assert!(!entry.content_visible, "Strict policy should withhold content when pending");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::atp::sdk::{DirectoryHandle, StreamHandle};
    use tempfile::TempDir;
    use std::fs;

    /// Integration test for directory handle early usability reporting
    #[test]
    fn test_directory_handle_early_usability_integration() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Create test files
        fs::write(temp_dir.path().join("small.txt"), "small content").expect("write small file");
        fs::write(temp_dir.path().join("large.bin"), "x".repeat(10000)).expect("write large file");

        let handle = DirectoryHandle::new(temp_dir.path()).expect("create directory handle");

        // Test early usability report
        let report = handle.early_usability_report(
            ConsumptionPolicy::VerifiedOnly,
            "integration-test-replay",
        );

        assert!(!report.metadata_paths.is_empty(), "Should have metadata paths");
        assert!(report.replay_pointer.contains("integration-test"), "Should include replay pointer");
    }

    /// Integration test for stream handle prefix consumption
    #[test]
    fn test_stream_handle_prefix_consumption_integration() {
        let handle = StreamHandle::new("test-stream", 10000)
            .expect("create stream handle");

        // Build verified prefix
        handle.mark_chunk_verified(0, 1000);
        handle.mark_chunk_verified(1000, 1000);

        // Test prefix consumption
        let verified_end = handle.verified_prefix_end();
        assert_eq!(verified_end, 2000, "Should have 2KB verified prefix");

        // Test consumption policy enforcement
        let can_consume_verified = handle.can_consume_range(0, 2000, ConsumptionPolicy::VerifiedOnly);
        assert!(can_consume_verified, "Should allow consumption of verified range");

        let can_consume_beyond = handle.can_consume_range(0, 3000, ConsumptionPolicy::VerifiedOnly);
        assert!(!can_consume_beyond, "Should reject consumption beyond verified range");
    }
}