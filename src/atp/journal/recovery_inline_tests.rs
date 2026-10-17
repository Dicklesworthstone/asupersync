    use super::*;
    use crate::atp::manifest::MerkleRoot;
    use crate::atp::object::{ContentId, ObjectId};

    fn test_object_id(name: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(name))
    }

    fn test_root(seed: u8) -> MerkleRoot {
        let mut hash = [0; 32];
        hash[0] = seed;
        MerkleRoot::new(hash)
    }

    fn test_auth_key() -> AuthKey {
        AuthKey::from_seed(42)
    }

    fn unsigned_tag() -> crate::security::AuthenticationTag {
        crate::security::AuthenticationTag::zero()
    }

    fn signed_record(record: JournalRecord) -> JournalRecord {
        record.with_signature(&test_auth_key())
    }

    fn process_test_record(
        ctx: &mut RecoveryContext,
        record: JournalRecord,
    ) -> Result<bool, RecoveryError> {
        let auth_key = test_auth_key();
        let record = record.with_signature(&auth_key);
        ctx.process_record(&record, &auth_key)
    }

    fn process_signed_record(
        ctx: &mut RecoveryContext,
        record: &JournalRecord,
    ) -> Result<bool, RecoveryError> {
        let auth_key = test_auth_key();
        ctx.process_record(record, &auth_key)
    }

    #[tokio::test]
    async fn test_cryptographic_integrity_validation() {
        use crate::atp::manifest::MerkleRoot;
        use crate::security::AuthenticationTag;

        let mut ctx = RecoveryContext::new();
        let auth_key = test_auth_key();

        // Create a valid record with correct signature
        let valid_record = JournalRecord::Offer {
            transfer_id: "test123".to_string(),
            object_id: test_object_id(b"test123"),
            manifest_root: MerkleRoot::new([0u8; 32]),
            total_size: 1024,
            timestamp: 1_000,
            auth_tag: AuthenticationTag::zero(),
        }
        .with_signature(&auth_key);

        // Should process successfully
        let result = ctx.process_record(&valid_record, &auth_key);
        assert!(result.is_ok(), "Valid record should be processed");

        // Create an invalid record with wrong signature
        let invalid_record = JournalRecord::Offer {
            transfer_id: "test456".to_string(),
            object_id: test_object_id(b"test456"),
            manifest_root: MerkleRoot::new([0u8; 32]),
            total_size: 2048,
            timestamp: 2_000,
            auth_tag: AuthenticationTag::zero(), // Wrong signature (all zeros)
        };

        // Should fail with InvalidSignature error
        let result = ctx.process_record(&invalid_record, &auth_key);
        assert!(
            matches!(result, Err(RecoveryError::InvalidSignature)),
            "Expected InvalidSignature error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_recovery_context_basic() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        // Process chunk progression
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::Offer {
                    transfer_id: transfer_id.clone(),
                    object_id: test_object_id(b"obj-1"),
                    manifest_root: test_root(1),
                    total_size: 8192,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    verified_hash: [0; 32],
                    timestamp: 3000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        let (bitmaps, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 3);
        assert_eq!(stats.transfers_recovered, 1);
        assert_eq!(stats.chunks_recovered, 1);

        let bitmap = &bitmaps[&transfer_id];
        assert_eq!(
            bitmap.get_chunk_state(chunk_offset),
            Some(ChunkState::Verified)
        );
    }

    #[tokio::test]
    async fn test_recovery_duplicate_detection() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        let record = signed_record(JournalRecord::ChunkReceived {
            transfer_id,
            chunk_offset,
            chunk_size: 1024,
            chunk_hash: [0; 32],
            timestamp: 2000,
            auth_tag: unsigned_tag(),
        });

        // First occurrence
        assert!(process_signed_record(&mut ctx, &record).unwrap());
        // Duplicate
        assert!(!process_signed_record(&mut ctx, &record).unwrap());

        let (_, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.duplicates_skipped, 1);
    }

    #[test]
    fn same_timestamp_distinct_payloads_are_not_duplicates() {
        let mut ctx = RecoveryContext::new();
        let key = test_auth_key();
        let transfer_id = "same-timestamp".to_string();
        let offer = |total_size| {
            signed_record(JournalRecord::Offer {
                transfer_id: transfer_id.clone(),
                object_id: test_object_id(b"same-timestamp"),
                manifest_root: test_root(3),
                total_size,
                timestamp: 1000,
                auth_tag: unsigned_tag(),
            })
        };
        let first = offer(1024);
        let second = offer(2048);
        assert!(ctx.process_record(&first, &key).unwrap());
        assert!(ctx.process_record(&second, &key).unwrap());
        assert!(!ctx.process_record(&first, &key).unwrap());
        assert!(!ctx.process_record(&second, &key).unwrap());

        // A payload change without re-signing must still fail before lookup.
        let mut forged = first.clone();
        if let JournalRecord::Offer { total_size, .. } = &mut forged {
            *total_size = 4096;
        }
        assert!(matches!(
            ctx.process_record(&forged, &key),
            Err(RecoveryError::InvalidSignature)
        ));
        process_test_record(
            &mut ctx,
            JournalRecord::ChunkReceived {
                transfer_id: transfer_id.clone(),
                chunk_offset: 0,
                chunk_size: 1024,
                chunk_hash: [0; 32],
                timestamp: 2000,
                auth_tag: unsigned_tag(),
            },
        )
        .unwrap();
        let (bitmaps, stats) = ctx.finalize();
        assert_eq!(bitmaps[&transfer_id].total_size(), 2048);
        assert_eq!(stats.total_records, 6);
        assert_eq!(stats.duplicates_skipped, 2);
    }

    #[test]
    fn rejected_record_remains_retryable_until_successfully_applied() {
        let mut ctx = RecoveryContext::new();
        let key = test_auth_key();
        let transfer_id = "retry-rejected".to_string();
        let verified = signed_record(JournalRecord::ChunkVerified {
            transfer_id: transfer_id.clone(),
            chunk_offset: 0,
            chunk_size: 1024,
            verified_hash: [7; 32],
            timestamp: 3000,
            auth_tag: unsigned_tag(),
        });

        // The real replay adapter skips invalid transitions, preserving later
        // records. Repeating a rejected record must still count as rejection.
        process_recovery_record(&mut ctx, &verified, &key).unwrap();
        process_recovery_record(&mut ctx, &verified, &key).unwrap();
        assert_eq!(ctx.stats.corrupted_skipped, 2);
        assert_eq!(ctx.stats.duplicates_skipped, 0);

        let received = signed_record(JournalRecord::ChunkReceived {
            transfer_id: transfer_id.clone(),
            chunk_offset: 0,
            chunk_size: 1024,
            chunk_hash: [7; 32],
            timestamp: 2000,
            auth_tag: unsigned_tag(),
        });
        process_recovery_record(&mut ctx, &received, &key).unwrap();
        assert!(ctx.process_record(&verified, &key).unwrap());
        assert!(!ctx.process_record(&verified, &key).unwrap());

        let (bitmaps, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 5);
        assert_eq!(stats.corrupted_skipped, 2);
        assert_eq!(stats.duplicates_skipped, 1);
        assert_eq!(stats.chunks_recovered, 1);
        assert_eq!(
            bitmaps[&transfer_id].get_chunk_state(0),
            Some(ChunkState::Verified)
        );
    }

    #[test]
    fn recovery_replay_skips_invalid_signature_without_discarding_valid_prefix() {
        let mut ctx = RecoveryContext::new();
        let auth_key = test_auth_key();
        let transfer_id = "prefix-survives".to_string();

        let valid_offer = signed_record(JournalRecord::Offer {
            transfer_id: transfer_id.clone(),
            object_id: test_object_id(b"prefix-survives"),
            manifest_root: test_root(3),
            total_size: 2048,
            timestamp: 1000,
            auth_tag: unsigned_tag(),
        });
        process_recovery_record(&mut ctx, &valid_offer, &auth_key).unwrap();

        let valid_received = signed_record(JournalRecord::ChunkReceived {
            transfer_id: transfer_id.clone(),
            chunk_offset: 0,
            chunk_size: 1024,
            chunk_hash: [1; 32],
            timestamp: 1100,
            auth_tag: unsigned_tag(),
        });
        process_recovery_record(&mut ctx, &valid_received, &auth_key).unwrap();

        let invalid_signature = JournalRecord::ChunkVerified {
            transfer_id: "tampered".to_string(),
            chunk_offset: 0,
            chunk_size: 1024,
            verified_hash: [9; 32],
            timestamp: 1200,
            auth_tag: unsigned_tag(),
        };
        process_recovery_record(&mut ctx, &invalid_signature, &auth_key).unwrap();

        let valid_verified = signed_record(JournalRecord::ChunkVerified {
            transfer_id: transfer_id.clone(),
            chunk_offset: 0,
            chunk_size: 1024,
            verified_hash: [2; 32],
            timestamp: 1300,
            auth_tag: unsigned_tag(),
        });
        process_recovery_record(&mut ctx, &valid_verified, &auth_key).unwrap();

        let (bitmaps, stats) = ctx.finalize();
        let bitmap = bitmaps.get(&transfer_id).expect("valid prefix recovered");

        assert_eq!(stats.total_records, 4);
        assert_eq!(stats.corrupted_skipped, 1);
        assert_eq!(bitmap.get_chunk_state(0), Some(ChunkState::Verified));
        assert!(!bitmaps.contains_key("tampered"));
    }

    #[test]
    fn recovery_finalize_preserves_recovered_bitmap_geometry() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "geometry".to_string();

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::Offer {
                    transfer_id: transfer_id.clone(),
                    object_id: test_object_id(b"geometry"),
                    manifest_root: test_root(4),
                    total_size: 2500,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        for (offset, chunk_size, timestamp) in
            [(0, 1024, 1100), (1024, 1024, 1200), (2048, 452, 1300)]
        {
            assert!(
                process_test_record(
                    &mut ctx,
                    JournalRecord::ChunkReceived {
                        transfer_id: transfer_id.clone(),
                        chunk_offset: offset,
                        chunk_size,
                        chunk_hash: [chunk_size as u8; 32],
                        timestamp,
                        auth_tag: unsigned_tag(),
                    }
                )
                .unwrap()
            );
        }

        let (bitmaps, stats) = ctx.finalize();
        let bitmap = bitmaps.get(&transfer_id).expect("bitmap recovered");
        let bitmap_stats = bitmap.get_stats();

        assert_eq!(stats.transfers_recovered, 1);
        assert_eq!(stats.chunks_recovered, 3);
        assert_eq!(bitmap_stats.total_size, 2500);
        assert_eq!(bitmap_stats.chunk_size, 1024);
        assert_eq!(bitmap_stats.total_chunks, 3);

        let decoded =
            ChunkBitmap::deserialize_from_bytes(&bitmap.serialize_to_bytes()).expect("round-trip");
        assert_eq!(decoded.total_size(), 2500);
        assert_eq!(decoded.chunk_size(), 1024);
        assert_eq!(decoded.entry_count(), 3);
    }

    #[test]
    fn bitmap_filename_parser_only_accepts_active_transfer_bitmaps() {
        assert_eq!(
            transfer_id_from_bitmap_path(Path::new("transfer_alpha.bitmap")),
            Some("alpha")
        );
        assert_eq!(
            transfer_id_from_bitmap_path(Path::new("transfer_alpha.bitmap.stale")),
            None
        );
        assert_eq!(
            transfer_id_from_bitmap_path(Path::new("alpha.bitmap")),
            None
        );
        assert_eq!(
            transfer_id_from_bitmap_path(Path::new("transfer_.bitmap")),
            None
        );
    }

    #[test]
    fn recovered_bitmap_loader_ignores_unadmitted_bitmap_without_deleting() {
        let stale_bitmap = ChunkBitmap::new("rolled-back".to_string(), 2048, 1024, 1000);
        let recovered_transfers = HashSet::new();

        let accepted = accept_recovered_bitmap(
            Path::new("transfer_rolled-back.bitmap"),
            stale_bitmap,
            &recovered_transfers,
        )
        .expect("unadmitted bitmap should be ignored without error");

        assert!(accepted.is_none());
    }

    #[test]
    fn recovered_bitmap_loader_rejects_path_payload_transfer_id_mismatch() {
        let bitmap = ChunkBitmap::new("payload-id".to_string(), 2048, 1024, 1000);
        let recovered_transfers = HashSet::from(["path-id".to_string()]);

        let err = accept_recovered_bitmap(
            Path::new("transfer_path-id.bitmap"),
            bitmap,
            &recovered_transfers,
        )
        .unwrap_err();

        assert!(err.to_string().contains("transfer id mismatch"));
    }

    #[test]
    fn recovered_bitmap_loader_rejects_quarantine_suffix_paths() {
        let err = required_transfer_id_from_bitmap_path(Path::new("transfer_alpha.bitmap.stale"))
            .unwrap_err();

        assert!(err.to_string().contains("transfer_<id>.bitmap"));
    }

    #[test]
    fn stale_bitmap_files_are_quarantined_without_touching_recovered_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let live_path = dir.path().join("transfer_live.bitmap");
        let stale_path = dir.path().join("transfer_stale.bitmap");
        let preexisting_stale = dir.path().join("transfer_stale.bitmap.stale");
        let expected_quarantine = dir.path().join("transfer_stale.bitmap.stale-1");

        let live_bitmap = ChunkBitmap::new("live".to_string(), 2048, 1024, 7);
        let stale_bitmap = ChunkBitmap::new("stale".to_string(), 1024, 512, 3);
        std::fs::write(&live_path, live_bitmap.serialize_to_bytes()).expect("write live bitmap");
        std::fs::write(&stale_path, stale_bitmap.serialize_to_bytes()).expect("write stale bitmap");
        std::fs::write(&preexisting_stale, b"occupied").expect("write existing quarantine");

        let recovered = HashMap::from([("live".to_string(), live_bitmap)]);
        let quarantined =
            futures_lite::future::block_on(quarantine_stale_bitmap_files(dir.path(), &recovered))
                .expect("quarantine stale bitmaps");

        assert_eq!(quarantined, 1);
        assert!(live_path.exists(), "recovered bitmap remains active");
        assert!(
            !stale_path.exists(),
            "stale bitmap is moved out of active namespace"
        );
        assert!(
            preexisting_stale.exists(),
            "existing quarantine file is not overwritten"
        );
        assert!(
            expected_quarantine.exists(),
            "stale bitmap gets unique quarantine path"
        );

        let quarantined_bitmap = ChunkBitmap::deserialize_from_bytes(
            &std::fs::read(expected_quarantine).expect("read quarantined bitmap"),
        )
        .expect("quarantined bitmap stays readable");
        assert_eq!(quarantined_bitmap.transfer_id(), "stale");
        assert_eq!(quarantined_bitmap.total_size(), 1024);
        assert_eq!(quarantined_bitmap.chunk_size(), 512);
    }

    #[tokio::test]
    async fn test_recovery_invalid_state_transition() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    verified_hash: [0; 32],
                    timestamp: 1500,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkWritten {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    file_path: "test".into(),
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::CommitComplete {
                    transfer_id: transfer_id.clone(),
                    final_path: "final".into(),
                    committed_size: 1024,
                    timestamp: 3000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Now try to go backwards to Received - should fail
        let result = process_test_record(
            &mut ctx,
            JournalRecord::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size: 1024,
                chunk_hash: [0; 32],
                timestamp: 4000,
                auth_tag: unsigned_tag(),
            },
        );

        assert!(matches!(
            result,
            Err(RecoveryError::InvalidStateTransition { .. })
        ));
    }

    #[tokio::test]
    async fn test_recovery_commit_rollback() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    verified_hash: [0; 32],
                    timestamp: 1500,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Write chunk
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkWritten {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    file_path: "test".into(),
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Commit intent
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::CommitIntent {
                    transfer_id: transfer_id.clone(),
                    final_manifest_root: test_root(2),
                    timestamp: 3000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Rollback instead of commit
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::Rollback {
                    transfer_id: transfer_id.clone(),
                    rollback_reason: "timeout".into(),
                    checkpoint_sequence: 0,
                    timestamp: 4000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        let (bitmaps, _) = ctx.finalize();
        assert!(!bitmaps.contains_key(&transfer_id));
    }

    #[test]
    fn rollback_discards_abandoned_geometry_before_retry() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "rollback-geometry".to_string();
        for offset in [0, 8192] {
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset: offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                },
            )
            .unwrap();
        }
        process_test_record(
            &mut ctx,
            JournalRecord::Rollback {
                transfer_id: transfer_id.clone(),
                rollback_reason: "retry".into(),
                checkpoint_sequence: 0,
                timestamp: 2000,
                auth_tag: unsigned_tag(),
            },
        )
        .unwrap();
        assert!(ctx.transfers[&transfer_id].chunk_states.is_empty());
        assert!(ctx.transfers[&transfer_id].chunk_sizes.is_empty());
        process_test_record(
            &mut ctx,
            JournalRecord::ChunkReceived {
                transfer_id: transfer_id.clone(),
                chunk_offset: 0,
                chunk_size: 256,
                chunk_hash: [1; 32],
                timestamp: 3000,
                auth_tag: unsigned_tag(),
            },
        )
        .unwrap();
        let (bitmaps, _) = ctx.finalize();
        let bitmap = &bitmaps[&transfer_id];
        assert_eq!(bitmap.total_size(), 256);
        assert_eq!(bitmap.chunk_size(), 256);
        assert_eq!(bitmap.entry_count(), 1);
        assert_eq!(bitmap.get_chunk_state(0), Some(ChunkState::Received));
    }

    #[test]
    fn rollback_keeps_geometry_for_retained_states() {
        let mut ctx = RecoveryContext::new();
        let transfer = ctx.ensure_transfer("retained-geometry");
        for (offset, state) in [
            (0, ChunkState::Committed),
            (256, ChunkState::Quarantined),
            (512, ChunkState::Invalidated),
            (768, ChunkState::Written),
        ] {
            let id = ChunkId::from_u64(offset);
            transfer.chunk_states.insert(id, state);
            transfer.record_chunk_geometry(id, 256, 1000);
        }
        RecoveryContext::rollback_uncommitted_chunks(transfer);
        assert_eq!(transfer.chunk_states.len(), 3);
        assert_eq!(transfer.chunk_sizes.len(), 3);
        for offset in [0, 256, 512] {
            assert_eq!(transfer.chunk_sizes[&ChunkId::from_u64(offset)], 256);
        }
        assert!(!transfer.chunk_sizes.contains_key(&ChunkId::from_u64(768)));
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DiskFaultPhase {
        JournalAppend,
        BitmapUpdate,
        ChunkWrite,
        Fsync,
        RepairDecode,
        ManifestWrite,
        TempFileRename,
        DirectoryFsync,
        Cleanup,
        ProofEmission,
        JournalCompaction,
    }

    impl DiskFaultPhase {
        const ALL: [Self; 11] = [
            Self::JournalAppend,
            Self::BitmapUpdate,
            Self::ChunkWrite,
            Self::Fsync,
            Self::RepairDecode,
            Self::ManifestWrite,
            Self::TempFileRename,
            Self::DirectoryFsync,
            Self::Cleanup,
            Self::ProofEmission,
            Self::JournalCompaction,
        ];
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CrashCut {
        Before,
        After,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RecoveryDisposition {
        Resume,
        Quarantine,
        Finalized,
    }

    struct DiskFaultModel {
        records: Vec<JournalRecord>,
        bitmap: ChunkBitmap,
        final_file_visible: bool,
        final_file_verified: bool,
        temp_renamed: bool,
        directory_synced: bool,
        cleanup_done: bool,
        proof_emitted: bool,
        compaction_seen: bool,
        live_children: usize,
        pending_obligations: usize,
    }

    struct RecoveredFault {
        disposition: RecoveryDisposition,
        chunk_state: Option<ChunkState>,
        repair_state: Option<ChunkState>,
        final_file_exposed: bool,
        proof_emitted: bool,
        compaction_seen: bool,
        live_children: usize,
        pending_obligations: usize,
        stats: RecoveryStats,
    }

    const MATRIX_TRANSFER: &str = "transfer-d5";
    const DATA_OFFSET: u64 = 0;
    const REPAIR_OFFSET: u64 = 4096;
    const CHUNK_SIZE: u64 = 4096;

    impl DiskFaultModel {
        fn new() -> Self {
            let mut bitmap =
                ChunkBitmap::new(MATRIX_TRANSFER.to_string(), CHUNK_SIZE * 2, CHUNK_SIZE, 1);
            bitmap.initialize_wanted_chunks(1);

            Self {
                records: Vec::new(),
                bitmap,
                final_file_visible: false,
                final_file_verified: false,
                temp_renamed: false,
                directory_synced: false,
                cleanup_done: false,
                proof_emitted: false,
                compaction_seen: false,
                live_children: 0,
                pending_obligations: 0,
            }
        }

        fn run_until(crash_phase: DiskFaultPhase, cut: CrashCut) -> Self {
            let mut model = Self::new();
            for phase in DiskFaultPhase::ALL {
                if phase == crash_phase && cut == CrashCut::Before {
                    break;
                }

                model.apply_phase(phase);

                if phase == crash_phase && cut == CrashCut::After {
                    break;
                }
            }
            model
        }

        fn apply_phase(&mut self, phase: DiskFaultPhase) {
            match phase {
                DiskFaultPhase::JournalAppend => {
                    self.records.push(signed_record(JournalRecord::Offer {
                        transfer_id: MATRIX_TRANSFER.to_string(),
                        object_id: test_object_id(b"fault-matrix-object"),
                        manifest_root: test_root(1),
                        total_size: CHUNK_SIZE * 2,
                        timestamp: 10,
                        auth_tag: unsigned_tag(),
                    }));
                }
                DiskFaultPhase::BitmapUpdate => {
                    self.bitmap.update_chunk_state(
                        DATA_OFFSET,
                        ChunkState::Received,
                        20,
                        Some([1; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkReceived {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: DATA_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            chunk_hash: [1; 32],
                            timestamp: 20,
                            auth_tag: unsigned_tag(),
                        }));
                }
                DiskFaultPhase::ChunkWrite => {
                    self.pending_obligations += 1;
                    self.bitmap.update_chunk_state(
                        DATA_OFFSET,
                        ChunkState::Verified,
                        30,
                        Some([2; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkVerified {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: DATA_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            verified_hash: [2; 32],
                            timestamp: 30,
                            auth_tag: unsigned_tag(),
                        }));
                    self.bitmap.update_chunk_state(
                        DATA_OFFSET,
                        ChunkState::Written,
                        40,
                        Some([2; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkWritten {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: DATA_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            file_path: "object.tmp".to_string(),
                            timestamp: 40,
                            auth_tag: unsigned_tag(),
                        }));
                    self.pending_obligations -= 1;
                }
                DiskFaultPhase::Fsync => {}
                DiskFaultPhase::RepairDecode => {
                    self.pending_obligations += 1;
                    self.bitmap.update_chunk_state(
                        REPAIR_OFFSET,
                        ChunkState::RepairDerived,
                        50,
                        Some([3; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::RepairDecode {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: REPAIR_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            source_chunks: vec![DATA_OFFSET],
                            timestamp: 50,
                            auth_tag: unsigned_tag(),
                        }));
                    self.bitmap.update_chunk_state(
                        REPAIR_OFFSET,
                        ChunkState::Verified,
                        60,
                        Some([4; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkVerified {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: REPAIR_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            verified_hash: [4; 32],
                            timestamp: 60,
                            auth_tag: unsigned_tag(),
                        }));
                    self.pending_obligations -= 1;
                }
                DiskFaultPhase::ManifestWrite => {
                    self.records
                        .push(signed_record(JournalRecord::CommitIntent {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            final_manifest_root: test_root(2),
                            timestamp: 70,
                            auth_tag: unsigned_tag(),
                        }));
                }
                DiskFaultPhase::TempFileRename => {
                    self.temp_renamed = true;
                    self.final_file_visible = true;
                }
                DiskFaultPhase::DirectoryFsync => {
                    self.directory_synced = true;
                }
                DiskFaultPhase::Cleanup => {
                    self.cleanup_done = true;
                    self.final_file_verified = true;
                    self.records
                        .push(signed_record(JournalRecord::CommitComplete {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            final_path: "object.final".to_string(),
                            committed_size: CHUNK_SIZE * 2,
                            timestamp: 80,
                            auth_tag: unsigned_tag(),
                        }));
                }
                DiskFaultPhase::ProofEmission => {
                    self.proof_emitted = true;
                    self.records.push(signed_record(JournalRecord::ProofDigest {
                        transfer_id: MATRIX_TRANSFER.to_string(),
                        proof_type: "receiver-finalizer".to_string(),
                        digest: [9; 32],
                        timestamp: 90,
                        auth_tag: unsigned_tag(),
                    }));
                }
                DiskFaultPhase::JournalCompaction => {
                    self.compaction_seen = true;
                    self.records
                        .push(signed_record(JournalRecord::CompactionBoundary {
                            generation: 1,
                            compacted_up_to_sequence: self.records.len() as u64,
                            timestamp: 100,
                            auth_tag: unsigned_tag(),
                        }));
                }
            }
        }

        fn recover(&self) -> RecoveredFault {
            let mut ctx = RecoveryContext::new();
            let mut invalid_record = false;
            for record in &self.records {
                if process_signed_record(&mut ctx, record).is_err() {
                    invalid_record = true;
                }
            }

            let (bitmaps, stats) = ctx.finalize();
            let bitmap = bitmaps.get(MATRIX_TRANSFER);
            let chunk_state = bitmap.and_then(|bitmap| bitmap.get_chunk_state(DATA_OFFSET));
            let repair_state = bitmap.and_then(|bitmap| bitmap.get_chunk_state(REPAIR_OFFSET));
            let commit_boundary_reached = self.cleanup_done;
            let unverified_final_file =
                (self.temp_renamed || self.directory_synced) && !commit_boundary_reached;
            let final_file_exposed =
                self.final_file_visible && self.final_file_verified && commit_boundary_reached;
            let disposition = if invalid_record || unverified_final_file {
                RecoveryDisposition::Quarantine
            } else if final_file_exposed && self.proof_emitted {
                RecoveryDisposition::Finalized
            } else {
                RecoveryDisposition::Resume
            };

            RecoveredFault {
                disposition,
                chunk_state,
                repair_state,
                final_file_exposed,
                proof_emitted: self.proof_emitted,
                compaction_seen: self.compaction_seen,
                live_children: self.live_children,
                pending_obligations: self.pending_obligations,
                stats,
            }
        }
    }

    #[test]
    fn disk_fault_matrix_recovers_to_resume_quarantine_or_finalized() {
        let mut before_cases = 0;
        let mut after_cases = 0;

        for phase in DiskFaultPhase::ALL {
            for cut in [CrashCut::Before, CrashCut::After] {
                let model = DiskFaultModel::run_until(phase, cut);
                let recovered = model.recover();

                match cut {
                    CrashCut::Before => before_cases += 1,
                    CrashCut::After => after_cases += 1,
                }

                assert_eq!(
                    recovered.live_children, 0,
                    "{phase:?} {cut:?} left live children"
                );
                assert_eq!(
                    recovered.pending_obligations, 0,
                    "{phase:?} {cut:?} leaked obligations"
                );
                if matches!(
                    phase,
                    DiskFaultPhase::TempFileRename | DiskFaultPhase::DirectoryFsync
                ) && cut == CrashCut::After
                {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Quarantine);
                    assert!(
                        !recovered.final_file_exposed,
                        "{phase:?} {cut:?} exposed an unverified final file"
                    );
                }

                let after_crash_cut = matches!(cut, CrashCut::After);

                if matches!(phase, DiskFaultPhase::Cleanup) && after_crash_cut {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Resume);
                    assert_eq!(recovered.chunk_state, Some(ChunkState::Committed));
                    assert!(recovered.final_file_exposed);
                    assert!(!recovered.proof_emitted);
                }

                if matches!(phase, DiskFaultPhase::ProofEmission) && after_crash_cut {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Finalized);
                    assert!(recovered.proof_emitted);
                }

                if matches!(phase, DiskFaultPhase::JournalCompaction) && after_crash_cut {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Finalized);
                    assert!(recovered.compaction_seen);
                    assert!(recovered.proof_emitted);
                }
            }
        }

        assert_eq!(before_cases, DiskFaultPhase::ALL.len());
        assert_eq!(after_cases, DiskFaultPhase::ALL.len());
    }

    #[test]
    fn disk_fault_matrix_preserves_repair_decode_and_compaction_records() {
        let recovered =
            DiskFaultModel::run_until(DiskFaultPhase::JournalCompaction, CrashCut::After).recover();

        assert_eq!(recovered.disposition, RecoveryDisposition::Finalized);
        assert_eq!(recovered.chunk_state, Some(ChunkState::Committed));
        assert_eq!(recovered.repair_state, Some(ChunkState::Verified));
        assert!(recovered.proof_emitted);
        assert!(recovered.compaction_seen);
        assert_eq!(recovered.stats.corrupted_skipped, 0);
    }
