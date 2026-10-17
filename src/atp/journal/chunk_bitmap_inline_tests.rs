    use super::*;

    #[test]
    fn test_chunk_state_properties() {
        assert!(ChunkState::Verified.has_data());
        assert!(ChunkState::Verified.is_verified());
        assert!(!ChunkState::Wanted.has_data());
        assert!(!ChunkState::Received.is_verified());
        assert!(ChunkState::Committed.is_final());
        assert!(!ChunkState::Verified.is_final());
    }

    #[test]
    fn test_chunk_entry_state_updates() {
        let mut entry = ChunkEntry::new(ChunkState::Wanted, 1000);

        // Forward transitions should work
        assert!(entry.update_state(ChunkState::Received, 1001));
        assert_eq!(entry.state, ChunkState::Received);

        assert!(entry.update_state(ChunkState::Verified, 1002));
        assert_eq!(entry.state, ChunkState::Verified);

        // Backward transitions should be rejected
        assert!(!entry.update_state(ChunkState::Received, 1003));
        assert_eq!(entry.state, ChunkState::Verified);

        // Invalidation should always work
        assert!(entry.update_state(ChunkState::Invalidated, 1004));
        assert_eq!(entry.state, ChunkState::Invalidated);
    }

    #[test]
    fn test_chunk_bitmap_basic() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 1024, 256, 1000);

        // Initialize wanted chunks
        bitmap.initialize_wanted_chunks(1001);
        assert_eq!(bitmap.chunks.len(), 4); // 1024 / 256 = 4 chunks

        // Check all chunks are wanted
        let wanted_chunks = bitmap.get_chunks_in_state(ChunkState::Wanted);
        assert_eq!(wanted_chunks.len(), 4);

        // Update first chunk to received
        assert!(bitmap.update_chunk_state(0, ChunkState::Received, 1002, None));
        assert_eq!(bitmap.get_chunk_state(0), Some(ChunkState::Received));

        // Update with hash
        let hash = [1u8; 32];
        assert!(bitmap.update_chunk_state(256, ChunkState::Verified, 1003, Some(hash)));

        let entry = bitmap.get_chunk_entry(256).unwrap();
        assert_eq!(entry.state, ChunkState::Verified);
        assert_eq!(entry.chunk_hash, Some(hash));
    }

    #[test]
    fn test_chunk_bitmap_ranges() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 1000, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        // Mark some chunks as verified
        bitmap.update_chunk_state(0, ChunkState::Verified, 1002, None);
        bitmap.update_chunk_state(100, ChunkState::Verified, 1003, None);
        bitmap.update_chunk_state(200, ChunkState::Verified, 1004, None);
        bitmap.update_chunk_state(400, ChunkState::Verified, 1005, None);

        let verified_ranges = bitmap.get_ranges_in_state(ChunkState::Verified);
        assert_eq!(verified_ranges.len(), 2);

        // First range: 0-300 (chunks 0, 100, 200)
        assert_eq!(verified_ranges[0], SparseRange::new(0, 300));

        // Second range: 400-500 (chunk 400)
        assert_eq!(verified_ranges[1], SparseRange::new(400, 500));
    }

    #[test]
    fn decoded_large_chunk_ranges_do_not_overflow() {
        let chunk_size = 1_u64 << 63;
        let mut bitmap = ChunkBitmap::new("large".to_string(), u64::MAX, chunk_size, 1);
        bitmap.initialize_wanted_chunks(2);
        assert!(bitmap.update_chunk_state(chunk_size, ChunkState::Verified, 3, None));
        let decoded = ChunkBitmap::deserialize_from_bytes(&bitmap.serialize_to_bytes()).unwrap();
        assert_eq!(
            decoded.get_ranges_in_state(ChunkState::Verified),
            vec![SparseRange::new(chunk_size, u64::MAX)]
        );
        assert_eq!(
            decoded.get_ranges_in_states(&[ChunkState::Wanted, ChunkState::Verified]),
            vec![SparseRange::new(0, u64::MAX)]
        );

        // Exercise a gap before the overflowing final chunk as well.
        let chunk_size = 1_u64 << 62;
        let mut sparse = ChunkBitmap::new("sparse-large".to_string(), u64::MAX, chunk_size, 1);
        assert!(sparse.update_chunk_state(0, ChunkState::Verified, 2, None));
        assert!(sparse.update_chunk_state(3 * chunk_size, ChunkState::Verified, 2, None));
        let decoded = ChunkBitmap::deserialize_from_bytes(&sparse.serialize_to_bytes()).unwrap();
        assert_eq!(
            decoded.get_ranges_in_state(ChunkState::Verified),
            vec![
                SparseRange::new(0, chunk_size),
                SparseRange::new(3 * chunk_size, u64::MAX),
            ]
        );
    }

    #[test]
    fn range_queries_exclude_invalid_entries_without_discarding_them() {
        let mut bitmap = ChunkBitmap::new("invalid-ranges".to_string(), 600, 256, 1);
        for offset in [0, 1, 256, 512, 600, 768, u64::MAX] {
            assert!(bitmap.update_chunk_state(offset, ChunkState::Verified, 2, None));
        }
        let expected = vec![SparseRange::new(0, 600)];
        assert_eq!(bitmap.get_ranges_in_state(ChunkState::Verified), expected);
        assert_eq!(
            bitmap.get_ranges_in_states(&[ChunkState::Verified, ChunkState::Committed]),
            expected
        );
        assert_eq!(bitmap.entry_count(), 7);
        assert_eq!(bitmap.get_chunk_state(u64::MAX), Some(ChunkState::Verified));
        assert_eq!(bitmap.get_stats().verified_chunks, 3);
        assert!(!bitmap.is_complete());
        assert!(ChunkBitmap::deserialize_from_bytes(&bitmap.serialize_to_bytes()).is_err());

        let mut imported = ChunkBitmap::new("imported-ranges".to_string(), 600, 256, 1);
        imported.import_state(bitmap.export_state());
        assert_eq!(imported.get_ranges_in_state(ChunkState::Verified), expected);
        assert_eq!(imported.entry_count(), 7);

        for (total_size, chunk_size, offset) in [(0, 256, 0), (512, 0, 0), (512, 256, 768)] {
            let mut invalid =
                ChunkBitmap::new("invalid-only".to_string(), total_size, chunk_size, 1);
            assert!(invalid.update_chunk_state(offset, ChunkState::Verified, 2, None));
            assert!(invalid.get_ranges_in_state(ChunkState::Verified).is_empty());
            assert!(
                invalid
                    .get_ranges_in_states(&[ChunkState::Verified])
                    .is_empty()
            );
            assert_eq!(invalid.entry_count(), 1);
        }
    }

    #[test]
    fn test_chunk_bitmap_stats() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 400, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        // Update chunk states
        bitmap.update_chunk_state(0, ChunkState::Received, 1002, None);
        bitmap.update_chunk_state(100, ChunkState::Verified, 1003, None);
        bitmap.update_chunk_state(200, ChunkState::Written, 1004, None);
        bitmap.update_chunk_state(300, ChunkState::Committed, 1005, None);

        let stats = bitmap.get_stats();
        assert_eq!(stats.total_chunks, 4);
        assert_eq!(stats.state_counts[&ChunkState::Received], 1);
        assert_eq!(stats.state_counts[&ChunkState::Verified], 1);
        assert_eq!(stats.state_counts[&ChunkState::Written], 1);
        assert_eq!(stats.state_counts[&ChunkState::Committed], 1);
        assert_eq!(stats.completed_chunks, 1);
        assert_eq!(stats.verified_chunks, 3); // verified + written + committed
        assert_eq!(stats.completion_ratio, 0.25);
        assert_eq!(stats.verification_ratio, 0.75);
    }

    #[test]
    fn test_chunk_bitmap_completion() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 200, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        assert!(!bitmap.is_complete());

        // Commit all chunks
        bitmap.update_chunk_state(0, ChunkState::Committed, 1002, None);
        bitmap.update_chunk_state(100, ChunkState::Committed, 1003, None);

        assert!(bitmap.is_complete());
    }

    #[test]
    fn sparse_committed_entry_does_not_make_bitmap_complete() {
        let mut bitmap = ChunkBitmap::new("sparse".to_string(), 1024, 256, 1000);

        assert!(bitmap.update_chunk_state(0, ChunkState::Committed, 1001, None));

        let stats = bitmap.get_stats();
        assert_eq!(stats.total_chunks, 4);
        assert_eq!(stats.completed_chunks, 1);
        assert_eq!(stats.state_counts[&ChunkState::Wanted], 3);
        assert_eq!(stats.completion_ratio, 0.25);
        assert_eq!(stats.verification_ratio, 0.25);
        assert!(!bitmap.is_complete());
    }

    #[test]
    fn out_of_grid_entries_do_not_count_toward_completion() {
        let mut bitmap = ChunkBitmap::new("bad-offset".to_string(), 512, 256, 1000);

        assert!(bitmap.update_chunk_state(512, ChunkState::Committed, 1001, None));

        let stats = bitmap.get_stats();
        assert_eq!(stats.total_chunks, 2);
        assert_eq!(stats.completed_chunks, 0);
        assert_eq!(stats.state_counts[&ChunkState::Wanted], 2);
        assert_eq!(stats.completion_ratio, 0.0);
        assert_eq!(stats.verification_ratio, 0.0);
        assert!(!bitmap.is_complete());
    }

    #[test]
    fn initialize_wanted_chunks_zero_chunk_size_does_not_panic() {
        // A crafted/corrupt bitmap with chunk_size == 0 must not divide-by-zero
        // or underflow in initialize_wanted_chunks (regression for the recovery
        // crash/DoS; see asupersync-59ik3w). It enumerates nothing.
        let mut bitmap = ChunkBitmap::new("zero".to_string(), 1_000_000, 0, 1000);
        bitmap.initialize_wanted_chunks(1001); // must not panic
        assert_eq!(
            bitmap.get_chunk_state(0),
            None,
            "no chunks enumerated for zero chunk_size"
        );
        assert!(!bitmap.is_complete());
    }

    #[test]
    fn test_chunk_bitmap_error_detection() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 200, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        assert!(!bitmap.has_errors());

        // Quarantine one chunk
        bitmap.update_chunk_state(0, ChunkState::Quarantined, 1002, None);
        assert!(bitmap.has_errors());

        // Invalidate another chunk
        bitmap.update_chunk_state(100, ChunkState::Invalidated, 1003, None);
        assert!(bitmap.has_errors());
    }

    #[test]
    fn test_chunk_bitmap_export_import() {
        let mut bitmap1 = ChunkBitmap::new("test_transfer".to_string(), 300, 100, 1000);
        bitmap1.initialize_wanted_chunks(1001);

        // Update some states
        bitmap1.update_chunk_state(0, ChunkState::Verified, 1002, Some([1u8; 32]));
        bitmap1.update_chunk_state(100, ChunkState::Written, 1003, Some([2u8; 32]));

        // Export and import
        let exported = bitmap1.export_state();
        let mut bitmap2 = ChunkBitmap::new("test_transfer".to_string(), 300, 100, 1000);
        bitmap2.import_state(exported);

        // Verify states match
        assert_eq!(bitmap2.get_chunk_state(0), Some(ChunkState::Verified));
        assert_eq!(bitmap2.get_chunk_state(100), Some(ChunkState::Written));
        assert_eq!(bitmap2.get_chunk_state(200), Some(ChunkState::Wanted)); // From export

        let entry1 = bitmap2.get_chunk_entry(0).unwrap(); // ubs:ignore - test oracle
        assert_eq!(entry1.chunk_hash, Some([1u8; 32]));
    }

    fn populated_bitmap() -> ChunkBitmap {
        let mut bitmap = ChunkBitmap::new("xfer-9".to_string(), 1024, 256, 5_000);
        bitmap.initialize_wanted_chunks(5_001);
        bitmap.update_chunk_state(0, ChunkState::Received, 5_010, None);
        bitmap.update_chunk_state(256, ChunkState::Verified, 5_020, Some([7u8; 32]));
        bitmap.update_chunk_state(512, ChunkState::Written, 5_030, Some([9u8; 32]));
        bitmap.update_chunk_state(768, ChunkState::Quarantined, 5_040, None);
        bitmap.set_chunk_metadata(256, "source".into(), "peer-a".into(), 5_050);
        bitmap.set_chunk_metadata(256, "verifier".into(), "sha256".into(), 5_060);
        bitmap
    }

    fn chunk_count_offset(transfer_id: &str) -> usize {
        ChunkBitmap::SERIALIZATION_MAGIC.len() + 1 + 4 + transfer_id.len() + 8 * 4
    }

    fn rewrite_crc(bytes: &mut [u8]) {
        let payload_len = bytes.len() - 4;
        let crc = crc32fast::hash(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        let original = populated_bitmap();
        let bytes = original.serialize_to_bytes();
        let decoded = ChunkBitmap::deserialize_from_bytes(&bytes).expect("decode succeeds");

        assert_eq!(decoded.transfer_id(), original.transfer_id());
        assert_eq!(decoded.total_size(), original.total_size());
        assert_eq!(decoded.chunk_size(), original.chunk_size());
        assert_eq!(decoded.created_at(), original.created_at());
        assert_eq!(decoded.updated_at(), original.updated_at());
        assert_eq!(decoded.entry_count(), original.entry_count());

        for offset in [0, 256, 512, 768] {
            let original_entry = original.get_chunk_entry(offset).expect("entry exists");
            let decoded_entry = decoded.get_chunk_entry(offset).expect("entry exists");
            assert_eq!(original_entry.state, decoded_entry.state);
            assert_eq!(
                original_entry.state_timestamp,
                decoded_entry.state_timestamp
            );
            assert_eq!(original_entry.chunk_hash, decoded_entry.chunk_hash);
            assert_eq!(original_entry.metadata, decoded_entry.metadata);
        }
    }

    #[test]
    fn serialization_is_deterministic() {
        let bitmap = populated_bitmap();
        let a = bitmap.serialize_to_bytes();
        let b = bitmap.serialize_to_bytes();
        assert_eq!(a, b, "two serializations of the same bitmap must be equal");

        // Reconstruct from decoded form and re-serialize -- canonical form survives a round trip.
        let decoded = ChunkBitmap::deserialize_from_bytes(&a).expect("decode succeeds");
        let re_serialized = decoded.serialize_to_bytes();
        assert_eq!(a, re_serialized);
    }

    #[test]
    fn deserialize_rejects_truncated_input() {
        let bytes = populated_bitmap().serialize_to_bytes();
        for cut in 0..bytes.len().min(80) {
            let result = ChunkBitmap::deserialize_from_bytes(&bytes[..cut]);
            assert!(
                matches!(
                    result,
                    Err(ChunkBitmapDecodeError::Truncated { .. }
                        | ChunkBitmapDecodeError::ChecksumMismatch { .. }
                        | ChunkBitmapDecodeError::BadMagic { .. })
                ),
                "cut={cut} must fail closed, got {result:?}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut bytes = populated_bitmap().serialize_to_bytes();
        bytes[0] = b'X';
        // Recompute checksum so the magic check is exercised, not the crc.
        let payload_len = bytes.len() - 4;
        let crc = crc32fast::hash(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&crc.to_le_bytes());
        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::BadMagic { .. }) => (),
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_unsupported_version() {
        let mut bytes = populated_bitmap().serialize_to_bytes();
        bytes[4] = 0xFE;
        let payload_len = bytes.len() - 4;
        let crc = crc32fast::hash(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&crc.to_le_bytes());
        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::UnsupportedVersion(0xFE)) => (),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_checksum_mismatch() {
        let mut bytes = populated_bitmap().serialize_to_bytes();
        // Flip a byte deep in the payload without recomputing the trailing CRC.
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x80;
        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::ChecksumMismatch { .. }) => (),
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_empty_bitmap_round_trips() {
        let original = ChunkBitmap::new("empty".to_string(), 0, 4096, 7);
        let bytes = original.serialize_to_bytes();
        let decoded = ChunkBitmap::deserialize_from_bytes(&bytes).expect("decode succeeds");
        assert_eq!(decoded.transfer_id(), "empty");
        assert_eq!(decoded.entry_count(), 0);
        assert_eq!(decoded.chunk_size(), 4096);
    }

    #[test]
    fn partial_serialized_bitmap_round_trips_but_is_not_complete() {
        let mut original = ChunkBitmap::new("partial".to_string(), 1024, 256, 7);
        original.update_chunk_state(0, ChunkState::Committed, 8, None);

        let decoded =
            ChunkBitmap::deserialize_from_bytes(&original.serialize_to_bytes()).expect("partial");
        let stats = decoded.get_stats();
        assert_eq!(stats.total_chunks, 4);
        assert_eq!(stats.completed_chunks, 1);
        assert_eq!(stats.state_counts[&ChunkState::Wanted], 3);
        assert_eq!(stats.completion_ratio, 0.25);
        assert!(!decoded.is_complete());
    }

    #[test]
    fn deserialize_rejects_zero_chunk_size_geometry() {
        let original = ChunkBitmap::new("bad-geometry".to_string(), 1024, 0, 7);
        match ChunkBitmap::deserialize_from_bytes(&original.serialize_to_bytes()) {
            Err(ChunkBitmapDecodeError::InvalidGeometry {
                total_size: 1024,
                chunk_size: 0,
            }) => (),
            other => panic!("expected InvalidGeometry, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_chunk_count_above_expected_without_preallocating() {
        let transfer_id = "bad-count";
        let original = ChunkBitmap::new(transfer_id.to_string(), 512, 256, 7);
        let mut bytes = original.serialize_to_bytes();
        let count_offset = chunk_count_offset(transfer_id);
        bytes[count_offset..count_offset + 4].copy_from_slice(&3u32.to_le_bytes());
        rewrite_crc(&mut bytes);

        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::InvalidChunkCount {
                expected: 2,
                actual: 3,
            }) => (),
            other => panic!("expected InvalidChunkCount, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_out_of_grid_chunk_offset() {
        let mut original = ChunkBitmap::new("bad-offset".to_string(), 512, 256, 7);
        original.update_chunk_state(512, ChunkState::Committed, 8, None);

        match ChunkBitmap::deserialize_from_bytes(&original.serialize_to_bytes()) {
            Err(ChunkBitmapDecodeError::InvalidChunkOffset {
                offset: 512,
                total_size: 512,
                chunk_size: 256,
            }) => (),
            other => panic!("expected InvalidChunkOffset, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_duplicate_chunk_offsets() {
        let transfer_id = "dupe-offset";
        let mut original = ChunkBitmap::new(transfer_id.to_string(), 512, 256, 7);
        original.update_chunk_state(0, ChunkState::Committed, 8, None);
        original.update_chunk_state(256, ChunkState::Committed, 9, None);
        let mut bytes = original.serialize_to_bytes();

        let first_entry_offset = chunk_count_offset(transfer_id) + 4;
        let second_entry_offset = first_entry_offset + 22;
        bytes[second_entry_offset..second_entry_offset + 8].copy_from_slice(&0u64.to_le_bytes());
        rewrite_crc(&mut bytes);

        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::DuplicateChunkOffset(0)) => (),
            other => panic!("expected DuplicateChunkOffset, got {other:?}"),
        }
    }
