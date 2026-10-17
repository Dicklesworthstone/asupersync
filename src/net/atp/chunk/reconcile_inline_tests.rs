    use super::*;

    fn fingerprint(seed: u64) -> ChunkFingerprint {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync::atp::chunk-reconcile::test-fingerprint::v1");
        hasher.update(seed.to_be_bytes());
        ChunkFingerprint(hasher.finalize().into())
    }

    #[test]
    fn reconciles_k_diffs_with_delta_scaled_wire_bytes() {
        let mut sender = Vec::new();
        let mut receiver = Vec::new();
        for seed in 0..1_000 {
            let id = fingerprint(seed);
            sender.push(id);
            receiver.push(id);
        }
        for seed in 1_000..1_007 {
            sender.push(fingerprint(seed));
        }
        for seed in 2_000..2_003 {
            receiver.push(fingerprint(seed));
        }

        let result = reconcile_chunk_sets(
            sender,
            receiver,
            &RatelessIbltConfig {
                initial_cell_count: 32,
                max_rounds: 8,
                hash_function_count: 3,
            },
        )
        .expect("IBLT should peel small deltas");

        assert_eq!(result.receiver_missing.len(), 7);
        assert_eq!(result.receiver_stale.len(), 3);
        assert!(result.estimated_wire_bytes < result.naive_sender_fingerprint_bytes);
    }

    #[test]
    fn undersized_decode_grows_until_success() {
        let sender: Vec<_> = (0..48).map(fingerprint).collect();
        let receiver: Vec<_> = (0..24).map(fingerprint).collect();

        let result = reconcile_chunk_sets(
            sender,
            receiver,
            &RatelessIbltConfig {
                initial_cell_count: 1,
                max_rounds: 10,
                hash_function_count: 3,
            },
        )
        .expect("rateless growth should eventually decode");

        assert!(result.rounds > 1);
        assert_eq!(result.receiver_missing.len(), 24);
        assert_eq!(result.symmetric_difference_chunks(), 24);
        assert!(result.receiver_stale.is_empty());
        assert!(!result.is_noop());
        assert!(result.requires_chunk_transfer());
    }

    #[test]
    fn delta_estimate_reports_exact_symmetric_difference() {
        let sender = [fingerprint(1), fingerprint(2), fingerprint(3)];
        let receiver = [fingerprint(2), fingerprint(4)];
        let estimate = estimate_chunk_set_delta(sender, receiver);

        assert_eq!(estimate.sender_unique_chunks, 3);
        assert_eq!(estimate.receiver_unique_chunks, 2);
        assert_eq!(estimate.shared_chunks, 1);
        assert_eq!(estimate.receiver_missing_chunks, 2);
        assert_eq!(estimate.receiver_stale_chunks, 1);
        assert_eq!(estimate.symmetric_difference_chunks, 3);
        assert_eq!(estimate.naive_sender_fingerprint_bytes, 96);
        assert!(estimate.recommended_initial_cells >= 8);

        let config = RatelessIbltConfig::default()
            .with_estimated_delta(estimate.symmetric_difference_chunks);
        assert_eq!(
            config.initial_cell_count,
            estimate.recommended_initial_cells
        );
    }

    #[test]
    fn reconcile_cdc_chunks_uses_content_hash_identity() {
        let shared = CdcChunkData {
            byte_offset: 0,
            size_bytes: 4,
            content_hash: fingerprint(10).0,
        };
        let sender_only = CdcChunkData {
            byte_offset: 4,
            size_bytes: 4,
            content_hash: fingerprint(11).0,
        };

        let result = reconcile_cdc_chunks(
            &[shared.clone(), sender_only.clone()],
            &[shared],
            &RatelessIbltConfig::default(),
        )
        .expect("CDC chunk reconciliation should decode");

        assert_eq!(
            result.receiver_missing,
            BTreeSet::from([ChunkFingerprint(sender_only.content_hash)])
        );
        assert!(result.receiver_stale.is_empty());
    }

    #[test]
    fn raw_hash_reconcile_reports_noop_for_equal_sets() {
        let hashes = [fingerprint(1).0, fingerprint(2).0, fingerprint(3).0];
        let result = reconcile_chunk_hashes(hashes, hashes, &RatelessIbltConfig::default())
            .expect("identical sets should decode as noop");

        assert!(result.is_noop());
        assert_eq!(result.symmetric_difference_chunks(), 0);
        assert!(!result.requires_chunk_transfer());
        assert!(result.wire_ratio_vs_naive_sender_fingerprints().is_some());
    }
