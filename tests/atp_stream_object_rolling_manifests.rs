//! Integration tests for ATP StreamObject rolling manifests.
//!
//! Tests cover the acceptance criteria for ATP-C7:
//! - StreamObject supports rolling manifest epochs with verified prefix records
//! - Early consumers can distinguish verified prefix, provisional tail, and final commit
//! - Resume works across stream epochs
//! - Proof bundle records prefix consumption and finalization semantics
//! - Producer cancellation, receiver cancellation, and final manifest mismatch scenarios

use asupersync::atp::manifest::{ChunkBoundary, ChunkStrategy};
use asupersync::atp::object::{ContentId, ObjectId};
use asupersync::atp::stream_object::*;

fn test_object_id() -> ObjectId {
    ObjectId::content(ContentId::new([42u8; 32]))
}

#[test]
fn test_rolling_manifest_epochs_basic_flow() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Producer creates epochs as stream is produced
    let epoch1 = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1024),
        EpochState::Verified,
        vec![], // Simplified, would have actual chunk boundaries
    );

    let epoch2 = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1024, 2048),
        EpochState::Provisional,
        vec![],
    );

    // Add epochs to manifest
    assert!(manifest.add_epoch(epoch1).is_ok());
    assert!(manifest.add_epoch(epoch2).is_ok());

    // Verify early consumer can distinguish states
    assert_eq!(manifest.verified_epochs().len(), 1);
    assert_eq!(manifest.provisional_epochs().len(), 1);
    assert_eq!(manifest.latest_verified_offset(), 1024);

    // Producer later verifies provisional epoch
    assert!(manifest.verify_epoch(2).is_ok());
    assert_eq!(manifest.verified_epochs().len(), 2);
    assert_eq!(manifest.provisional_epochs().len(), 0);
    assert_eq!(manifest.latest_verified_offset(), 2048);

    // Add final epoch
    let final_epoch = StreamEpoch::new(
        3,
        object_id.clone(),
        ByteRange::new(2048, 3072),
        EpochState::Final,
        vec![],
    );

    assert!(manifest.add_epoch(final_epoch).is_ok());
    assert!(manifest.is_complete());
    assert!(manifest.final_manifest_hash.is_some());
}

#[test]
fn test_early_consumer_safety_verified_only() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Add mixed verified and provisional epochs
    let epoch1 = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1000),
        EpochState::Verified,
        vec![],
    );
    let epoch2 = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Provisional,
        vec![],
    );
    let epoch3 = StreamEpoch::new(
        3,
        object_id.clone(),
        ByteRange::new(2000, 3000),
        EpochState::Verified,
        vec![],
    );

    manifest.add_epoch(epoch1).unwrap();
    manifest.add_epoch(epoch2).unwrap();
    manifest.add_epoch(epoch3).unwrap();

    // Consumer with verified-only policy
    let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);

    // Should only see verified ranges (epoch 1 and 3, but 3 can't be consumed due to gap)
    assert!(consumer.data_available());
    let safe_range = consumer.next_safe_range().unwrap();
    assert_eq!(safe_range, ByteRange::new(0, 1000)); // Only first verified epoch

    // Consume verified data
    consumer.advance_consumption(500);
    assert_eq!(consumer.consumption_progress(), 50.0);

    // Still has more verified data
    assert!(consumer.data_available());
    let remaining = consumer.next_safe_range().unwrap();
    assert_eq!(remaining, ByteRange::new(500, 1000));
}

#[test]
fn test_early_consumer_safety_allow_provisional() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Add mixed epochs
    let epoch1 = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1000),
        EpochState::Verified,
        vec![],
    );
    let epoch2 = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Provisional,
        vec![],
    );

    manifest.add_epoch(epoch1).unwrap();
    manifest.add_epoch(epoch2).unwrap();

    // Consumer allowing provisional data
    let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);

    // Should see both verified and provisional ranges
    assert!(consumer.data_available());
    let safe_range = consumer.next_safe_range().unwrap();
    assert_eq!(safe_range, ByteRange::new(0, 2000)); // Both epochs

    // Consume all available data
    consumer.advance_consumption(2000);
    assert_eq!(consumer.consumption_progress(), 100.0);
    assert!(!consumer.data_available());
}

#[test]
fn test_stream_resume_across_epochs() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Create a stream with multiple verified epochs
    for i in 0..5 {
        let epoch = StreamEpoch::new(
            i + 1,
            object_id.clone(),
            ByteRange::new(i * 1000, (i + 1) * 1000),
            EpochState::Verified,
            vec![],
        );
        manifest.add_epoch(epoch).unwrap();
    }

    // Test resumption at various points

    // Resume at beginning of epoch 2
    let checkpoint = manifest.resumption_checkpoint(1000);
    assert!(checkpoint.is_some());
    let cp = checkpoint.unwrap();
    assert_eq!(cp.epoch_sequence, 1);
    assert_eq!(cp.byte_offset, 1000);

    // Resume in middle of stream
    let checkpoint = manifest.resumption_checkpoint(3500);
    assert!(checkpoint.is_some());
    let cp = checkpoint.unwrap();
    assert_eq!(cp.epoch_sequence, 3); // Last complete epoch before 3500
    assert_eq!(cp.byte_offset, 3000);

    // Resume near end
    let checkpoint = manifest.resumption_checkpoint(4999);
    assert!(checkpoint.is_some());
    let cp = checkpoint.unwrap();
    assert_eq!(cp.epoch_sequence, 4);
    assert_eq!(cp.byte_offset, 4000);

    // Resume beyond available data
    let checkpoint = manifest.resumption_checkpoint(10000);
    assert!(checkpoint.is_some());
    let cp = checkpoint.unwrap();
    assert_eq!(cp.epoch_sequence, 5); // Last epoch
    assert_eq!(cp.byte_offset, 5000);
}

#[test]
fn test_proof_bundle_consumption_record() {
    let object_id = test_object_id();
    let consumed_epochs = vec![1, 2, 3];

    // Create proof record for complete consumption
    let mut proof = StreamProofRecord::new(
        object_id.clone(),
        consumed_epochs.clone(),
        3072,
        ConsumptionPolicy::VerifiedOnly,
        true, // fully_consumed
    );

    assert_eq!(proof.object_id, object_id);
    assert_eq!(proof.consumed_epochs, consumed_epochs);
    assert_eq!(proof.final_offset, 3072);
    assert_eq!(proof.consumption_policy, "verified_only");
    assert!(proof.fully_consumed);

    // Sign the proof
    let signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
    proof.sign(signature.clone());
    assert_eq!(proof.consumer_signature, Some(signature));

    // Create proof for partial consumption
    let partial_proof = StreamProofRecord::new(
        object_id,
        vec![1, 2],
        2048,
        ConsumptionPolicy::AllowProvisional,
        false, // not fully consumed
    );

    assert_eq!(partial_proof.consumption_policy, "allow_provisional");
    assert!(!partial_proof.fully_consumed);
}

#[test]
fn test_producer_cancellation_scenario() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Producer starts stream normally
    let epoch1 = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1000),
        EpochState::Verified,
        vec![],
    );
    let epoch2 = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Provisional,
        vec![],
    );

    manifest.add_epoch(epoch1).unwrap();
    manifest.add_epoch(epoch2).unwrap();

    // Producer cancels - invalidate provisional epoch
    assert!(manifest.invalidate_epoch(2).is_ok());

    // Check state after cancellation
    assert_eq!(manifest.verified_epochs().len(), 1);
    assert_eq!(manifest.provisional_epochs().len(), 0);

    let invalidated_epoch_count = manifest
        .epochs
        .iter()
        .filter(|e| e.state == EpochState::Invalidated)
        .count();
    assert_eq!(invalidated_epoch_count, 1);

    // Consumer should only see verified data
    let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
    let safe_range = consumer.next_safe_range().unwrap();
    assert_eq!(safe_range, ByteRange::new(0, 1000));
}

#[test]
fn test_receiver_cancellation_scenario() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Set up stream with multiple epochs
    for i in 0..3 {
        let epoch = StreamEpoch::new(
            i + 1,
            object_id.clone(),
            ByteRange::new(i * 1000, (i + 1) * 1000),
            EpochState::Verified,
            vec![],
        );
        manifest.add_epoch(epoch).unwrap();
    }

    // Consumer starts processing
    let mut consumer = PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::VerifiedOnly);
    consumer.advance_consumption(1500); // Process 1.5 epochs

    // Receiver cancellation - create proof of partial consumption
    let consumed_epochs = vec![1, 2]; // Fully consumed epochs
    let proof = StreamProofRecord::new(
        object_id,
        consumed_epochs,
        1500,
        ConsumptionPolicy::VerifiedOnly,
        false, // not fully consumed due to cancellation
    );

    assert_eq!(proof.final_offset, 1500);
    assert!(!proof.fully_consumed);

    // Consumer should be able to resume from last checkpoint
    let checkpoint = manifest.resumption_checkpoint(1500);
    assert!(checkpoint.is_some());
    let cp = checkpoint.unwrap();
    assert_eq!(cp.byte_offset, 1000); // Can resume from epoch 1 boundary
}

#[test]
fn test_final_manifest_mismatch_detection() {
    let object_id = test_object_id();
    let mut manifest1 = StreamManifest::new(object_id.clone());
    let mut manifest2 = StreamManifest::new(object_id.clone());

    // Create identical streams initially
    for i in 0..3 {
        let epoch1 = StreamEpoch::new(
            i + 1,
            object_id.clone(),
            ByteRange::new(i * 1000, (i + 1) * 1000),
            EpochState::Verified,
            vec![],
        );
        let epoch2 = epoch1.clone();

        manifest1.add_epoch(epoch1).unwrap();
        manifest2.add_epoch(epoch2).unwrap();
    }

    let final_chunk1 = ChunkBoundary {
        index: 0,
        byte_offset: 3000,
        size_bytes: 1000,
        content_hash: [0x11; 32],
        strategy: ChunkStrategy::FixedSize,
        metadata: None,
    };
    let final_chunk2 = ChunkBoundary {
        content_hash: [0x22; 32],
        ..final_chunk1.clone()
    };

    // Make them final
    let final_epoch1 = StreamEpoch::new(
        4,
        object_id.clone(),
        ByteRange::new(3000, 4000),
        EpochState::Final,
        vec![final_chunk1],
    );
    let final_epoch2 = StreamEpoch::new(
        4,
        object_id.clone(),
        ByteRange::new(3000, 4000),
        EpochState::Final,
        vec![final_chunk2],
    );

    // Introduce a canonical content difference in the final epoch.

    manifest1.add_epoch(final_epoch1).unwrap();
    manifest2.add_epoch(final_epoch2).unwrap();

    // Final manifest hashes should be different due to different signatures
    assert!(manifest1.final_manifest_hash.is_some());
    assert!(manifest2.final_manifest_hash.is_some());
    assert_ne!(manifest1.final_manifest_hash, manifest2.final_manifest_hash);
}

#[test]
fn test_epoch_sequence_validation() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Add first epoch
    let epoch1 = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch1).is_ok());

    // Try to add epoch with same sequence number
    let epoch_dup = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch_dup).is_err());

    // Try to add epoch with lower sequence number
    let epoch_lower = StreamEpoch::new(
        0,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch_lower).is_err());

    // Valid sequential epoch should work
    let epoch2 = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch2).is_ok());
}

#[test]
fn test_byte_range_continuity_validation() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // First epoch must start at 0
    let invalid_first = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(100, 200),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(invalid_first).is_err());

    // Valid first epoch
    let epoch1 = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch1).is_ok());

    // Gap in ranges should be rejected
    let epoch_gap = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1500, 2000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch_gap).is_err());

    // Overlap should be rejected
    let epoch_overlap = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(500, 1500),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch_overlap).is_err());

    // Valid continuous epoch
    let epoch2 = StreamEpoch::new(
        2,
        object_id.clone(),
        ByteRange::new(1000, 2000),
        EpochState::Verified,
        vec![],
    );
    assert!(manifest.add_epoch(epoch2).is_ok());
}

#[test]
fn test_epoch_state_transitions() {
    let object_id = test_object_id();
    let mut manifest = StreamManifest::new(object_id.clone());

    // Add provisional epoch
    let epoch = StreamEpoch::new(
        1,
        object_id.clone(),
        ByteRange::new(0, 1000),
        EpochState::Provisional,
        vec![],
    );
    manifest.add_epoch(epoch).unwrap();

    assert_eq!(manifest.total_provisional_bytes, 1000);
    assert_eq!(manifest.total_verified_bytes, 0);

    // Verify the epoch
    assert!(manifest.verify_epoch(1).is_ok());
    assert_eq!(manifest.total_provisional_bytes, 0);
    assert_eq!(manifest.total_verified_bytes, 1000);

    // Try to verify again - should be no-op
    assert!(manifest.verify_epoch(1).is_err()); // Should fail since already verified

    // Try to verify non-existent epoch
    assert!(manifest.verify_epoch(999).is_err());
}
