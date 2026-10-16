    use super::*;
    use crate::atp::dedupe::{build_canonical_dedup_payload_parts, build_dedup_payload_set};
    use crate::atp::delta::{
        DeltaResyncMode, PersistentChunkManifest, ReceiverCasCoverage,
        plan_incremental_resync_with_receiver_coverage, reconstruct_manifest_bytes,
    };

    fn manifest(
        store: &mut ContentAddressedChunkStore,
        tree_id: &str,
        chunks: &[&[u8]],
    ) -> PersistentChunkManifest {
        let report = store
            .ingest_ordered_chunks(chunks.iter().copied())
            .expect("ingest chunks");
        PersistentChunkManifest::new(tree_id, report.chunks).expect("manifest")
    }

    fn pattern_bytes(len: usize, seed: u32) -> Vec<u8> {
        (0..len)
            .map(|idx| {
                let value = idx as u32;
                value
                    .wrapping_mul(seed | 1)
                    .wrapping_add(value / 7)
                    .wrapping_add(seed.rotate_left(5)) as u8
            })
            .collect()
    }

    #[test]
    fn reconcile_places_one_unique_payload_at_multiple_target_offsets() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"repeat"[..], &b"middle"[..], &b"repeat"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        let (store, report) =
            reconcile_dedup_payload_set(&sender, &receiver_store, &payload_set).expect("reconcile");

        assert_eq!(report.unique_payloads, 2);
        assert_eq!(report.inserted_unique_payloads, 2);
        assert_eq!(report.reused_receiver_payloads, 0);
        assert_eq!(report.duplicate_logical_chunks, 1);
        assert_eq!(report.reconstructed_bytes, sender.total_size_bytes);
        let rebuilt = reconstruct_manifest_bytes(&sender, &store).expect("reconstruct");
        assert_eq!(rebuilt, b"repeatmiddlerepeat".as_slice());
    }

    #[test]
    fn reconcile_reports_preseeded_receiver_payload_reuse() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"alpha"[..], &b"beta"[..], &b"alpha"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        receiver_store
            .insert(b"alpha")
            .expect("preseed receiver CAS");
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        let (store, report) =
            reconcile_dedup_payload_set(&sender, &receiver_store, &payload_set).expect("reconcile");

        assert_eq!(report.unique_payloads, 2);
        assert_eq!(report.inserted_unique_payloads, 1);
        assert_eq!(report.reused_receiver_payloads, 1);
        assert_eq!(report.duplicate_logical_chunks, 1);
        assert_eq!(report.reconstructed_bytes, sender.total_size_bytes);
        let rebuilt = reconstruct_manifest_bytes(&sender, &store).expect("reconstruct");
        assert_eq!(rebuilt, b"alphabetaalpha".as_slice());
    }

    #[test]
    fn reconcile_existing_receiver_store_reconstructs_tree_rename_without_payload() {
        let alpha = pattern_bytes(32 * 1024, 11);
        let beta = pattern_bytes(24 * 1024, 29);
        let gamma = pattern_bytes(40 * 1024, 47);
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = manifest(
            &mut receiver_store,
            "old-tree",
            &[alpha.as_slice(), beta.as_slice(), gamma.as_slice()],
        );
        let sender = manifest(
            &mut sender_store,
            "renamed-tree",
            &[gamma.as_slice(), alpha.as_slice(), beta.as_slice()],
        );
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);

        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.missing_chunks.len(), 0);
        assert_eq!(plan.missing_bytes, 0);

        let report =
            reconcile_existing_receiver_store_and_reconstruct(&sender, &receiver_store, &plan)
                .expect("zero-payload reconcile");

        assert_eq!(report.metadata_wire_bytes, 0);
        assert_eq!(report.unique_payload_wire_bytes, 0);
        assert_eq!(report.compact_wire_bytes, 0);
        assert_eq!(report.logical_missing_bytes, 0);
        assert_eq!(report.reconcile.unique_payloads, 0);
        assert_eq!(
            report.reconcile.reconstructed_bytes,
            sender.total_size_bytes
        );
        assert_eq!(
            report.reconstructed_bytes,
            [gamma.as_slice(), alpha.as_slice(), beta.as_slice()].concat()
        );
        sender
            .verify_store_coverage(&report.store)
            .expect("receiver CAS covers renamed target");
    }

    #[test]
    fn reconcile_existing_receiver_store_reconstructs_larger_tree_reorder_without_payload() {
        let chunks: Vec<Vec<u8>> = (0..16)
            .map(|idx| pattern_bytes(64 * 1024 + idx * 1024, 101 + idx as u32 * 17))
            .collect();
        let receiver_refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        let reorder = [7usize, 3, 0, 15, 11, 5, 9, 2, 10, 1, 14, 4, 8, 13, 6, 12];
        let sender_refs: Vec<&[u8]> = reorder
            .iter()
            .map(|&chunk_idx| chunks[chunk_idx].as_slice())
            .collect();
        let expected: Vec<u8> = sender_refs
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = manifest(&mut receiver_store, "tree-before-rename", &receiver_refs);
        let sender = manifest(&mut sender_store, "tree-after-rename", &sender_refs);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);

        assert!(sender.total_size_bytes > 1024 * 1024);
        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.missing_chunks.len(), 0);
        assert_eq!(plan.missing_bytes, 0);

        let report =
            reconcile_existing_receiver_store_and_reconstruct(&sender, &receiver_store, &plan)
                .expect("larger zero-payload reorder reconcile");

        assert_eq!(report.compact_wire_bytes, 0);
        assert_eq!(report.reconstructed_bytes, expected);
        sender
            .verify_store_coverage(&report.store)
            .expect("receiver CAS covers larger reordered target");
    }

    #[test]
    fn reconcile_applies_canonical_dedup_payload_parts() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"repeat"[..], &b"middle"[..], &b"repeat"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");
        let metadata = payload_set.send_set.to_canonical_bytes().expect("metadata");
        let payload_bytes = payload_set
            .to_canonical_payload_bytes()
            .expect("payload bytes");

        let (store, report) = reconcile_canonical_dedup_payload_parts(
            &sender,
            &receiver_store,
            &plan,
            &metadata,
            &payload_bytes,
        )
        .expect("canonical reconcile");

        assert_eq!(report.unique_payloads, 2);
        assert_eq!(report.duplicate_logical_chunks, 1);
        assert_eq!(report.reconstructed_bytes, sender.total_size_bytes);
        let rebuilt = reconstruct_manifest_bytes(&sender, &store).expect("reconstruct");
        assert_eq!(rebuilt, b"repeatmiddlerepeat".as_slice());
    }

    #[test]
    fn reconcile_canonical_dedup_parts_reconstructs_target_bytes() {
        let repeated = vec![b'r'; 4096];
        let unique = vec![b'u'; 1024];
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let parts =
            build_canonical_dedup_payload_parts(&plan, &sender_store).expect("canonical parts");

        let report = reconcile_canonical_dedup_parts_and_reconstruct(
            &sender,
            &receiver_store,
            &plan,
            &parts,
        )
        .expect("reconstruct canonical parts");

        assert!(report.saves_bytes());
        assert_eq!(report.saved_wire_bytes(), parts.saved_bytes());
        assert_eq!(report.metadata_wire_bytes, parts.metadata_wire_bytes);
        assert_eq!(
            report.unique_payload_wire_bytes,
            parts.unique_payload_wire_bytes
        );
        assert_eq!(report.compact_wire_bytes, parts.compact_wire_bytes);
        assert_eq!(report.logical_missing_bytes, sender.total_size_bytes);
        assert_eq!(
            report.duplicate_missing_chunks,
            parts.duplicate_missing_chunks
        );
        assert_eq!(
            report.duplicate_missing_bytes,
            parts.duplicate_missing_bytes
        );
        assert_eq!(report.reconcile.unique_payloads, 2);
        assert_eq!(report.reconcile.duplicate_logical_chunks, 1);
        assert_eq!(
            report.reconstructed_bytes,
            [repeated.as_slice(), unique.as_slice(), repeated.as_slice()].concat()
        );
        sender
            .verify_store_coverage(&report.store)
            .expect("verified reconstructed store");
    }

    #[test]
    fn reconcile_canonical_dedup_payload_parts_reconstruct_from_wire_bytes() {
        let repeated = vec![b'w'; 4096];
        let unique = vec![b'z'; 1024];
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let parts =
            build_canonical_dedup_payload_parts(&plan, &sender_store).expect("canonical parts");

        let report = reconcile_canonical_dedup_payload_parts_and_reconstruct(
            &sender,
            &receiver_store,
            &plan,
            &parts.metadata_bytes,
            &parts.unique_payload_bytes,
        )
        .expect("reconstruct raw canonical parts");

        assert!(report.saves_bytes());
        assert_eq!(report.metadata_wire_bytes, parts.metadata_wire_bytes);
        assert_eq!(
            report.unique_payload_wire_bytes,
            parts.unique_payload_wire_bytes
        );
        assert_eq!(report.compact_wire_bytes, parts.compact_wire_bytes);
        assert_eq!(report.logical_missing_bytes, parts.logical_missing_bytes);
        assert_eq!(
            report.duplicate_missing_chunks,
            parts.duplicate_missing_chunks
        );
        assert_eq!(
            report.duplicate_missing_bytes,
            parts.duplicate_missing_bytes
        );
        assert_eq!(
            report.reconstructed_bytes,
            [repeated.as_slice(), unique.as_slice(), repeated.as_slice()].concat()
        );
    }

    #[test]
    fn reconcile_canonical_dedup_parts_reconstructs_larger_repeated_tree_payloads() {
        let repeated = pattern_bytes(512 * 1024, 61);
        let unique = pattern_bytes(128 * 1024, 83);
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "large-tree",
            &[
                repeated.as_slice(),
                unique.as_slice(),
                repeated.as_slice(),
                repeated.as_slice(),
            ],
        );
        let receiver = manifest(&mut receiver_store, "large-tree", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let parts =
            build_canonical_dedup_payload_parts(&plan, &sender_store).expect("canonical parts");

        let report = reconcile_canonical_dedup_parts_and_reconstruct(
            &sender,
            &receiver_store,
            &plan,
            &parts,
        )
        .expect("large repeated reconcile");

        assert!(report.saves_bytes());
        assert_eq!(report.unique_payload_wire_bytes, 640 * 1024);
        assert_eq!(report.logical_missing_bytes, sender.total_size_bytes);
        assert_eq!(report.duplicate_missing_chunks, 2);
        assert_eq!(report.duplicate_missing_bytes, 1024 * 1024);
        assert!(report.saved_wire_bytes() > 900 * 1024);
        assert_eq!(report.reconcile.unique_payloads, 2);
        assert_eq!(report.reconcile.inserted_unique_payloads, 2);
        assert_eq!(report.reconcile.duplicate_logical_chunks, 2);
        assert_eq!(
            report.reconstructed_bytes,
            [
                repeated.as_slice(),
                unique.as_slice(),
                repeated.as_slice(),
                repeated.as_slice()
            ]
            .concat()
        );
    }

    #[test]
    fn reconcile_canonical_dedup_parts_fail_closed_before_reconstruct() {
        let repeated = vec![b'r'; 4096];
        let unique = vec![b'u'; 1024];
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let mut parts =
            build_canonical_dedup_payload_parts(&plan, &sender_store).expect("canonical parts");

        parts.unique_payload_bytes[0] ^= 0x40;
        let err = reconcile_canonical_dedup_parts_and_reconstruct(
            &sender,
            &receiver_store,
            &plan,
            &parts,
        )
        .expect_err("tampered canonical parts");

        assert!(matches!(err, DeltaError::ChunkPayloadHashMismatch { .. }));
    }

    #[test]
    fn reconcile_canonical_dedup_payload_parts_fail_closed_before_reconstruct() {
        let repeated = vec![b'w'; 4096];
        let unique = vec![b'z'; 1024];
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let parts =
            build_canonical_dedup_payload_parts(&plan, &sender_store).expect("canonical parts");
        let mut unique_payload_bytes = parts.unique_payload_bytes.clone();
        unique_payload_bytes[0] ^= 0x40;

        let err = reconcile_canonical_dedup_payload_parts_and_reconstruct(
            &sender,
            &receiver_store,
            &plan,
            &parts.metadata_bytes,
            &unique_payload_bytes,
        )
        .expect_err("tampered canonical wire parts");

        assert!(matches!(err, DeltaError::ChunkPayloadHashMismatch { .. }));
    }

    #[test]
    fn reconcile_fails_closed_on_tampered_unique_payload() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(&mut sender_store, "tree-a", &[&b"alpha"[..], &b"alpha"[..]]);
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let mut payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");
        payload_set.payloads[0].payload[0] ^= 0x40;

        let err = reconcile_dedup_payload_set(&sender, &receiver_store, &payload_set)
            .expect_err("tampered payload");

        assert!(matches!(err, DeltaError::ChunkPayloadHashMismatch { .. }));
    }
