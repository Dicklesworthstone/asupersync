    use super::*;
    use crate::atp::manifest::ProofStrength;

    fn criteria() -> ChunkReuseCriteria {
        ChunkReuseCriteria {
            max_age_seconds: 3600,
            min_proof_strength: ProofStrength::Basic,
            require_same_algorithm: true,
        }
    }

    fn fastcdc_params() -> CdcParameters {
        CdcParameters {
            window_size: 64,
            min_chunk_size: 512,
            max_chunk_size: 4096,
            normalization_constant: 0x1021,
        }
    }

    fn fastcdc_fixture(record_count: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for record_index in 0..record_count {
            data.extend_from_slice(format!("record-{record_index:04}:").as_bytes());
            for payload_index in 0..80 {
                data.push(b'a' + ((record_index + payload_index) % 26) as u8);
            }
            data.push(b'\n');
        }
        data
    }

    fn chunk_hash_set(chunks: &[CdcChunkData]) -> std::collections::BTreeSet<[u8; 32]> {
        chunks.iter().map(|chunk| chunk.content_hash).collect()
    }

    fn test_cdc_chunk(byte_offset: u64, data: &[u8]) -> CdcChunkData {
        CdcChunkData {
            byte_offset,
            size_bytes: data.len() as u64,
            content_hash: CdcEngine::compute_content_hash(data),
        }
    }

    #[test]
    fn gear_hash_matches_known_vector() {
        let mut hash = RollingHash::new(64);
        for &byte in b"asupersync-fastcdc" {
            hash.update(byte);
        }

        assert_eq!(hash.hash(), 0x5240_b854_273d_098e);
    }

    #[test]
    fn fastcdc_chunks_cover_input_byte_exactly() {
        let mut engine = CdcEngine::new();
        let params = fastcdc_params();
        let data = fastcdc_fixture(220);

        let chunks = engine.compute_cdc_boundaries(&data, &params).unwrap();

        assert!(!chunks.is_empty());
        let mut reconstructed = Vec::new();
        let mut expected_offset = 0u64;
        for chunk in &chunks {
            assert_eq!(chunk.byte_offset, expected_offset);
            assert!(chunk.size_bytes <= params.max_chunk_size);

            let start = usize::try_from(chunk.byte_offset).unwrap();
            let end = usize::try_from(chunk.byte_offset + chunk.size_bytes).unwrap();
            reconstructed.extend_from_slice(&data[start..end]);
            expected_offset += chunk.size_bytes;
        }

        assert_eq!(expected_offset, data.len() as u64);
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn fastcdc_resynchronizes_after_prefix_and_insert() {
        let mut engine = CdcEngine::new();
        let params = fastcdc_params();
        let original = fastcdc_fixture(420);

        let mut prefixed = b"new-header-line\n".to_vec();
        prefixed.extend_from_slice(&original);

        let insert_at = original.len() / 2;
        let mut inserted = original[..insert_at].to_vec();
        inserted.extend_from_slice(b"inserted-record:payload payload payload\n");
        inserted.extend_from_slice(&original[insert_at..]);

        let original_chunks = engine.compute_cdc_boundaries(&original, &params).unwrap();
        let prefixed_chunks = engine.compute_cdc_boundaries(&prefixed, &params).unwrap();
        let inserted_chunks = engine.compute_cdc_boundaries(&inserted, &params).unwrap();

        let original_hashes = chunk_hash_set(&original_chunks);
        let prefixed_hashes = chunk_hash_set(&prefixed_chunks);
        let inserted_hashes = chunk_hash_set(&inserted_chunks);
        let prefix_common = original_hashes.intersection(&prefixed_hashes).count();
        let insert_common = original_hashes.intersection(&inserted_hashes).count();

        assert!(prefix_common * 3 >= original_hashes.len() * 2);
        assert!(insert_common * 2 >= original_hashes.len());
    }

    #[test]
    fn delta_floor_zero_when_receiver_already_has_target_chunks() {
        let chunks = vec![
            test_cdc_chunk(0, b"alpha"),
            test_cdc_chunk(5, b"beta"),
            test_cdc_chunk(9, b"gamma"),
        ];

        let estimate = CdcEngine::estimate_delta_floor(&chunks, &chunks, Some(0));

        assert_eq!(estimate.receiver_unique_chunk_count, 3);
        assert_eq!(estimate.sender_unique_chunk_count, 3);
        assert_eq!(estimate.shared_chunk_count, 3);
        assert_eq!(estimate.sender_missing_chunk_count, 0);
        assert_eq!(estimate.estimated_floor_bytes_on_wire, 0);
        assert_eq!(estimate.observed_gap_to_floor, None);
    }

    #[test]
    fn delta_floor_counts_unique_missing_target_chunks_once() {
        let old_a = test_cdc_chunk(0, b"alpha");
        let old_b = test_cdc_chunk(5, b"beta");
        let new_c = test_cdc_chunk(5, b"carrot");
        let duplicate_new_c = test_cdc_chunk(11, b"carrot");

        let estimate = CdcEngine::estimate_delta_floor(
            &[old_a.clone(), old_b],
            &[old_a, new_c, duplicate_new_c],
            Some(18),
        );

        assert_eq!(estimate.shared_chunk_count, 1);
        assert_eq!(estimate.sender_missing_chunk_count, 1);
        assert_eq!(estimate.receiver_stale_chunk_count, 1);
        assert_eq!(estimate.sender_missing_bytes, 6);
        assert_eq!(estimate.receiver_stale_bytes, 4);
        assert_eq!(estimate.symmetric_difference_bytes, 10);
        assert_eq!(estimate.estimated_floor_bytes_on_wire, 6);
        assert_eq!(estimate.observed_gap_to_floor, Some(3.0));
    }

    #[test]
    fn same_transfer_reuses_own_scoped_chunk() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[identity.content_hash], &criteria());

        assert_eq!(reusable, vec![identity]);
    }

    #[test]
    fn different_transfer_cannot_reuse_private_scope() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-b", &[identity.content_hash], &criteria());

        assert!(reusable.is_empty());
    }

    #[test]
    fn conflicting_registered_scopes_fail_closed_to_global_only_reuse() {
        let mut manager = ChunkReuseManager::new();
        let private_a = ChunkIdentity::from_data(b"aaa", "scope-a", ProofStrength::Basic);
        let private_b = ChunkIdentity::from_data(b"bbb", "scope-b", ProofStrength::Basic);
        let global = ChunkIdentity::from_data(b"ccc", "", ProofStrength::Basic);

        manager
            .register_transfer_chunk("mixed", &private_a)
            .unwrap();
        manager
            .register_transfer_chunk("mixed", &private_b)
            .unwrap();
        manager.cache.store_chunk(&private_a, b"aaa").unwrap();
        manager.cache.store_chunk(&private_b, b"bbb").unwrap();
        manager.cache.store_chunk(&global, b"ccc").unwrap();

        let reusable = manager.find_reusable_chunks(
            "mixed",
            &[
                private_a.content_hash,
                private_b.content_hash,
                global.content_hash,
            ],
            &criteria(),
        );

        assert_eq!(reusable, vec![global]);
    }

    #[test]
    fn replacing_same_identity_does_not_inflate_cache_size() {
        let data = b"repeat";
        let identity = ChunkIdentity::from_data(data, "scope-a", ProofStrength::Basic);
        let mut cache = ChunkCache::new(1024);

        cache.store_chunk(&identity, data).unwrap();
        cache.store_chunk(&identity, data).unwrap();

        let stats = cache.get_statistics();
        assert_eq!(stats.total_chunks, 1);
        assert_eq!(stats.current_size, data.len() as u64);
    }

    #[test]
    fn oversized_chunk_is_rejected_without_cache_growth() {
        let data = b"too-large";
        let identity = ChunkIdentity::from_data(data, "scope-a", ProofStrength::Basic);
        let mut cache = ChunkCache::new(1);

        let err = cache.store_chunk(&identity, data).unwrap_err();

        assert!(matches!(
            err,
            ChunkingProfileError::InvalidChunkParameters(_)
        ));
        assert_eq!(cache.get_statistics().current_size, 0);
    }

    #[test]
    fn zero_sized_cache_reports_zero_utilization() {
        let cache = ChunkCache::new(0);

        assert_eq!(cache.get_statistics().utilization, 0.0);
    }

    #[test]
    fn reuse_criteria_rejects_low_proof_chunks() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();
        let strict_criteria = ChunkReuseCriteria {
            min_proof_strength: ProofStrength::Enhanced,
            ..criteria()
        };

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[identity.content_hash], &strict_criteria);

        assert!(reusable.is_empty());
    }

    #[test]
    fn reuse_criteria_rejects_stale_chunks() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();
        manager
            .cache
            .chunks
            .get_mut(&identity)
            .unwrap()
            .last_accessed = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap();
        let stale_rejecting_criteria = ChunkReuseCriteria {
            max_age_seconds: 1,
            ..criteria()
        };

        let reusable = manager.find_reusable_chunks(
            "transfer-a",
            &[identity.content_hash],
            &stale_rejecting_criteria,
        );

        assert!(reusable.is_empty());
    }

    #[test]
    fn reuse_criteria_rejects_non_canonical_algorithm_when_required() {
        let mut manager = ChunkReuseManager::new();
        let mut identity =
            ChunkIdentity::from_data(b"chunk-data", "transfer-transfer-a", ProofStrength::Basic);
        identity.verification.algorithm = "custom-hash".to_string();
        manager.cache.store_chunk(&identity, b"chunk-data").unwrap();
        manager
            .register_transfer_chunk("transfer-a", &identity)
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[identity.content_hash], &criteria());

        assert!(reusable.is_empty());
    }

    #[test]
    fn same_content_in_multiple_authorized_scopes_returns_one_candidate() {
        let mut manager = ChunkReuseManager::new();
        let data = b"shared-content";
        let scoped =
            ChunkIdentity::from_data(data, "transfer-transfer-a", ProofStrength::Cryptographic);
        let global = ChunkIdentity::from_data(data, "", ProofStrength::Basic);

        manager.cache.store_chunk(&scoped, data).unwrap();
        manager.cache.store_chunk(&global, data).unwrap();
        manager
            .register_transfer_chunk("transfer-a", &scoped)
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[scoped.content_hash], &criteria());

        assert_eq!(reusable.len(), 1);
        assert_eq!(reusable[0].content_hash, scoped.content_hash);
        assert_eq!(reusable[0].size_bytes, scoped.size_bytes);
        assert_eq!(
            reusable[0].verification.proof_strength,
            ProofStrength::Cryptographic
        );
    }
