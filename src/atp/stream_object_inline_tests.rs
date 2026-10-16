    use super::*;
    use crate::atp::manifest::ChunkStrategy;
    use crate::atp::object::ContentId;

    fn test_object_id() -> ObjectId {
        ObjectId::content(ContentId::new([1u8; 32]))
    }

    #[test]
    fn test_byte_range_operations() {
        let range1 = ByteRange::new(0, 100);
        let range2 = ByteRange::new(100, 200);
        let range3 = ByteRange::new(50, 150);

        assert_eq!(range1.size(), 100);
        assert!(!range1.is_empty());
        assert!(range1.contains(50));
        assert!(!range1.contains(100));

        // Adjacent ranges don't overlap but can merge
        assert!(!range1.overlaps(&range2));
        assert!(range1.merge(&range2).is_some());

        // Overlapping ranges
        assert!(range1.overlaps(&range3));
        let merged = range1.merge(&range3).unwrap();
        assert_eq!(merged, ByteRange::new(0, 150));
    }

    #[test]
    fn test_stream_epoch_creation() {
        let object_id = test_object_id();
        let byte_range = ByteRange::new(0, 1024);
        let chunk_boundaries = vec![];

        let epoch = StreamEpoch::new(
            1,
            object_id.clone(),
            byte_range,
            EpochState::Verified,
            chunk_boundaries,
        );

        assert_eq!(epoch.epoch_sequence, 1);
        assert_eq!(epoch.object_id, object_id);
        assert_eq!(epoch.byte_range, byte_range);
        assert!(epoch.is_verified());
        assert!(!epoch.is_final());
        assert!(!epoch.is_provisional());
        assert_eq!(epoch.verified_size(), 1024);
    }

    #[test]
    fn epoch_hash_uses_full_deterministic_sha256() {
        let object_id = test_object_id();
        let boundary = ChunkBoundary {
            index: 7,
            byte_offset: 128,
            size_bytes: 256,
            content_hash: [0x5a; 32],
            strategy: ChunkStrategy::ContentDefined,
            metadata: None,
        };

        let hash_a = StreamEpoch::compute_epoch_hash(
            &object_id,
            3,
            &ByteRange::new(128, 384),
            std::slice::from_ref(&boundary),
        );
        let hash_b = StreamEpoch::compute_epoch_hash(
            &object_id,
            3,
            &ByteRange::new(128, 384),
            std::slice::from_ref(&boundary),
        );
        let hash_c = StreamEpoch::compute_epoch_hash(
            &object_id,
            4,
            &ByteRange::new(128, 384),
            std::slice::from_ref(&boundary),
        );

        assert_eq!(hash_a, hash_b);
        assert_ne!(hash_a, hash_c);
        assert!(hash_a[8..].iter().any(|&byte| byte != 0));
    }

    #[test]
    fn test_stream_manifest_lifecycle() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        assert!(!manifest.is_complete());
        assert_eq!(manifest.total_verified_bytes, 0);
        assert_eq!(manifest.verified_epochs().len(), 0);

        // Add first epoch
        let epoch1 = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(0, 1024),
            EpochState::Verified,
            vec![],
        );
        manifest.add_epoch(epoch1).unwrap();

        assert_eq!(manifest.total_verified_bytes, 1024);
        assert_eq!(manifest.verified_epochs().len(), 1);

        // Add provisional epoch
        let epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(1024, 2048),
            EpochState::Provisional,
            vec![],
        );
        manifest.add_epoch(epoch2).unwrap();

        assert_eq!(manifest.total_provisional_bytes, 1024);
        assert_eq!(manifest.provisional_epochs().len(), 1);

        // Verify provisional epoch
        manifest.verify_epoch(2).unwrap();
        assert_eq!(manifest.total_verified_bytes, 2048);
        assert_eq!(manifest.total_provisional_bytes, 0);

        // Add final epoch
        let epoch3 = StreamEpoch::new(
            3,
            object_id.clone(),
            ByteRange::new(2048, 3072),
            EpochState::Final,
            vec![],
        );
        manifest.add_epoch(epoch3).unwrap();

        assert!(manifest.is_complete());
        assert!(manifest.final_manifest_hash.is_some());
    }

    #[test]
    fn test_prefix_consumer() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        // Add verified epoch
        let epoch1 = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(0, 1024),
            EpochState::Verified,
            vec![],
        );
        manifest.add_epoch(epoch1).unwrap();

        // Add provisional epoch
        let epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(1024, 2048),
            EpochState::Provisional,
            vec![],
        );
        manifest.add_epoch(epoch2).unwrap();

        // Test verified-only consumer
        let mut consumer = PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::VerifiedOnly);
        assert!(consumer.data_available());

        let safe_range = consumer.next_safe_range().unwrap();
        assert_eq!(safe_range, ByteRange::new(0, 1024));

        consumer.advance_consumption(512);
        assert_eq!(consumer.consumption_progress(), 50.0);

        // Test provisional-allowing consumer
        let consumer_prov = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        let safe_range_prov = consumer_prov.next_safe_range().unwrap();
        assert_eq!(safe_range_prov, ByteRange::new(0, 2048));
    }

    #[test]
    fn prefix_exposure_record_includes_verified_prefix_proof_fields() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        let record = consumer.exposure_record(Some("replay:prefix-verified".to_string()));

        assert_eq!(record.object_id, object_id);
        assert_eq!(record.prefix_range, Some(ByteRange::new(0, 100)));
        assert_eq!(record.verified_state, PrefixVerifiedState::Verified);
        assert_eq!(record.exposure_decision, PrefixExposureDecision::Expose);
        assert_eq!(record.invalidation_reason, None);
        assert_eq!(
            record.replay_pointer.as_deref(),
            Some("replay:prefix-verified")
        );
        assert_eq!(record.consumption_policy, "verified_only");
    }

    #[test]
    fn prefix_exposure_record_marks_provisional_policy_caveat() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        let record = consumer.exposure_record(Some("replay:prefix-provisional".to_string()));

        assert_eq!(record.object_id, object_id);
        assert_eq!(record.prefix_range, Some(ByteRange::new(0, 200)));
        assert_eq!(record.verified_state, PrefixVerifiedState::Provisional);
        assert_eq!(record.exposure_decision, PrefixExposureDecision::Expose);
        assert_eq!(record.consumption_policy, "allow_provisional");
        assert_eq!(
            record.replay_pointer.as_deref(),
            Some("replay:prefix-provisional")
        );
    }

    #[test]
    fn verified_only_prefix_stops_before_provisional_gap() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        assert_eq!(manifest.latest_verified_offset(), 300);
        assert_eq!(manifest.verified_prefix_end(), 100);

        let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        assert_eq!(consumer.next_safe_range(), Some(ByteRange::new(0, 100)));

        consumer.advance_consumption(100);
        assert!(!consumer.data_available());
        assert_eq!(consumer.next_safe_range(), None);
    }

    #[test]
    fn provisional_policy_prefix_stops_before_invalidated_gap() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Invalidated,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        assert_eq!(consumer.next_safe_range(), Some(ByteRange::new(0, 100)));
    }

    #[test]
    fn prefix_consumer_advance_caps_at_available_prefix() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id,
                ByteRange::new(0, 1024),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        consumer.advance_consumption(2048);

        assert_eq!(consumer.consumption_progress(), 100.0);
        assert_eq!(consumer.next_safe_range(), None);
    }

    #[test]
    fn prefix_consumer_refresh_reports_invalidated_consumed_bytes() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let mut consumer =
            PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::AllowProvisional);
        assert_eq!(consumer.next_safe_range(), Some(ByteRange::new(0, 200)));
        consumer.advance_consumption(200);

        manifest.invalidate_epoch(2).unwrap();
        let refresh = consumer.refresh_manifest(manifest).unwrap();

        assert_eq!(refresh.previous_prefix_end, 200);
        assert_eq!(refresh.available_prefix_end, 100);
        assert_eq!(
            refresh.invalidated_consumed_range,
            Some(ByteRange::new(100, 200))
        );
        assert_eq!(refresh.consumption_offset, 100);
        assert_eq!(consumer.next_safe_range(), None);
    }

    #[test]
    fn refresh_with_exposure_record_logs_invalidation_reason_and_replay() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let mut consumer =
            PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::AllowProvisional);
        consumer.advance_consumption(200);

        manifest.invalidate_epoch(2).unwrap();
        let (refresh, record) = consumer
            .refresh_manifest_with_exposure_record(
                manifest,
                Some("epoch 2 manifest hash mismatch".to_string()),
                Some("replay:prefix-invalidated".to_string()),
            )
            .unwrap();

        assert_eq!(
            refresh.invalidated_consumed_range,
            Some(ByteRange::new(100, 200))
        );
        assert_eq!(record.object_id, object_id);
        assert_eq!(record.prefix_range, Some(ByteRange::new(100, 200)));
        assert_eq!(record.verified_state, PrefixVerifiedState::Invalidated);
        assert_eq!(record.exposure_decision, PrefixExposureDecision::Withhold);
        assert_eq!(
            record.invalidation_reason.as_deref(),
            Some("epoch 2 manifest hash mismatch")
        );
        assert_eq!(
            record.replay_pointer.as_deref(),
            Some("replay:prefix-invalidated")
        );
    }

    #[test]
    fn prefix_consumer_refresh_rejects_different_object() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id,
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        let other_manifest = StreamManifest::new(ObjectId::content(ContentId::new([2u8; 32])));

        assert!(consumer.refresh_manifest(other_manifest).is_err());
    }

    #[test]
    fn resumption_checkpoint_stops_before_invalidated_gap() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Invalidated,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let checkpoint = manifest.resumption_checkpoint(300).unwrap();
        assert_eq!(checkpoint.epoch_sequence, 1);
        assert_eq!(checkpoint.byte_offset, 100);
    }

    #[test]
    fn resumption_checkpoint_advances_after_provisional_gap_is_verified() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let checkpoint_before = manifest.resumption_checkpoint(300).unwrap();
        assert_eq!(checkpoint_before.epoch_sequence, 1);
        assert_eq!(checkpoint_before.byte_offset, 100);

        manifest.verify_epoch(2).unwrap();
        let checkpoint_after = manifest.resumption_checkpoint(300).unwrap();
        assert_eq!(checkpoint_after.epoch_sequence, 3);
        assert_eq!(checkpoint_after.byte_offset, 300);
    }

    #[test]
    fn test_resumption_checkpoint() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        // Add multiple verified epochs
        for i in 0..3 {
            let epoch = StreamEpoch::new(
                i + 1,
                object_id.clone(),
                ByteRange::new(i * 1024, (i + 1) * 1024),
                EpochState::Verified,
                vec![],
            );
            manifest.add_epoch(epoch).unwrap();
        }

        // Test checkpoint at middle of stream
        let checkpoint = manifest.resumption_checkpoint(2500);
        assert!(checkpoint.is_some());

        let cp = checkpoint.unwrap();
        assert_eq!(cp.epoch_sequence, 2); // Last epoch that ends before 2500
        assert_eq!(cp.byte_offset, 2048); // End of epoch 2
    }

    #[test]
    fn test_stream_proof_record() {
        let object_id = test_object_id();
        let consumed_epochs = vec![1, 2, 3];

        let mut proof = StreamProofRecord::new(
            object_id.clone(),
            consumed_epochs.clone(),
            3072,
            ConsumptionPolicy::VerifiedOnly,
            true,
        );

        assert_eq!(proof.object_id, object_id);
        assert_eq!(proof.consumed_epochs, consumed_epochs);
        assert_eq!(proof.final_offset, 3072);
        assert_eq!(proof.consumption_policy, "verified_only");
        assert!(proof.fully_consumed);
        assert!(proof.prefix_exposures.is_empty());
        assert!(proof.consumer_signature.is_none());

        // Test signing
        proof.sign(vec![0xFF; 64]);
        assert!(proof.consumer_signature.is_some());
    }

    #[test]
    fn stream_proof_record_collects_prefix_exposure_records() {
        let object_id = test_object_id();
        let exposure = PrefixExposureRecord::new(
            object_id.clone(),
            Some(ByteRange::new(0, 1024)),
            PrefixVerifiedState::Verified,
            PrefixExposureDecision::Expose,
            ConsumptionPolicy::VerifiedOnly,
            Some("replay:proof-exposure".to_string()),
        );
        let mut proof = StreamProofRecord::new(
            object_id,
            vec![1],
            1024,
            ConsumptionPolicy::VerifiedOnly,
            false,
        );

        proof.record_prefix_exposure(exposure);

        assert_eq!(proof.prefix_exposures.len(), 1);
        assert_eq!(
            proof.prefix_exposures[0].replay_pointer.as_deref(),
            Some("replay:proof-exposure")
        );
        assert_eq!(
            proof.prefix_exposures[0].prefix_range,
            Some(ByteRange::new(0, 1024))
        );
    }

    #[test]
    fn prefix_exposure_artifact_serializes_required_log_fields() -> Result<(), serde_json::Error> {
        let object_id = test_object_id();
        let mut exposure = PrefixExposureRecord::new(
            object_id.clone(),
            Some(ByteRange::new(100, 200)),
            PrefixVerifiedState::Invalidated,
            PrefixExposureDecision::Withhold,
            ConsumptionPolicy::AllowProvisional,
            Some("replay:prefix-artifact".to_string()),
        );
        exposure.invalidation_reason = Some("epoch manifest hash mismatch".to_string());

        let artifact = exposure.to_artifact();
        let json = serde_json::to_value(&artifact)?;

        assert_eq!(artifact.object_id, object_id_artifact_id(&object_id));
        assert_eq!(artifact.object_hash, object_id.as_hex());
        assert_eq!(artifact.prefix_range, Some(ByteRange::new(100, 200)));
        assert_eq!(artifact.verified_state, "invalidated");
        assert_eq!(artifact.exposure_decision, "withhold");
        assert_eq!(
            artifact.invalidation_reason.as_deref(),
            Some("epoch manifest hash mismatch")
        );
        assert_eq!(
            artifact.replay_pointer.as_deref(),
            Some("replay:prefix-artifact")
        );
        assert_eq!(artifact.consumption_policy, "allow_provisional");
        assert_eq!(json["prefix_range"]["start"], 100);
        assert_eq!(json["verified_state"], "invalidated");
        Ok(())
    }

    #[test]
    fn stream_prefix_proof_artifact_round_trips_exposure_records() -> Result<(), serde_json::Error>
    {
        let object_id = test_object_id();
        let exposure = PrefixExposureRecord::new(
            object_id.clone(),
            Some(ByteRange::new(0, 1024)),
            PrefixVerifiedState::Verified,
            PrefixExposureDecision::Expose,
            ConsumptionPolicy::VerifiedOnly,
            Some("replay:stream-proof".to_string()),
        );
        let mut proof = StreamProofRecord::new(
            object_id.clone(),
            vec![1, 2],
            1024,
            ConsumptionPolicy::VerifiedOnly,
            false,
        );
        proof.record_prefix_exposure(exposure);
        proof.sign(vec![0xAB, 0xCD]);

        let artifact = proof.to_artifact();
        let encoded = serde_json::to_string(&artifact)?;
        let decoded: StreamPrefixProofArtifact = serde_json::from_str(&encoded)?;

        assert_eq!(decoded.schema_version, STREAM_PREFIX_PROOF_ARTIFACT_SCHEMA);
        assert_eq!(decoded.object_id, object_id_artifact_id(&object_id));
        assert_eq!(decoded.object_hash, object_id.as_hex());
        assert_eq!(decoded.consumed_epochs, vec![1, 2]);
        assert_eq!(decoded.final_offset, 1024);
        assert_eq!(decoded.consumption_policy, "verified_only");
        assert!(!decoded.fully_consumed);
        assert_eq!(decoded.consumer_signature_hex.as_deref(), Some("abcd"));
        assert_eq!(decoded.prefix_exposures.len(), 1);
        assert_eq!(
            decoded.prefix_exposures[0].prefix_range,
            Some(ByteRange::new(0, 1024))
        );
        assert_eq!(decoded.prefix_exposures[0].verified_state, "verified");
        assert_eq!(decoded.prefix_exposures[0].exposure_decision, "expose");
        assert_eq!(
            decoded.prefix_exposures[0].replay_pointer.as_deref(),
            Some("replay:stream-proof")
        );
        Ok(())
    }

    #[test]
    fn test_epoch_validation() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        // First epoch must start at 0
        let invalid_epoch = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(100, 200), // Invalid start
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(invalid_epoch).is_err());

        // Valid first epoch
        let valid_epoch1 = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(0, 100),
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(valid_epoch1).is_ok());

        // Second epoch must be continuous
        let invalid_epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(200, 300), // Gap from 100-200
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(invalid_epoch2).is_err());

        // Valid continuous epoch
        let valid_epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(100, 200),
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(valid_epoch2).is_ok());
    }
