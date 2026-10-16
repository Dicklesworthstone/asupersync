    use super::*;
    use crate::atp::delta::{
        PersistentChunkManifest, ReceiverCasCoverage,
        plan_incremental_resync_with_receiver_coverage,
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

    #[test]
    fn dedupe_send_set_transmits_duplicate_content_once() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"alpha"[..], &b"beta"[..], &b"alpha"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);

        let send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");

        assert_eq!(send_set.logical_missing_chunk_count(), 3);
        assert_eq!(send_set.unique_chunk_count(), 2);
        assert_eq!(send_set.logical_missing_bytes, 14);
        assert_eq!(send_set.unique_payload_bytes, 9);
        assert_eq!(send_set.duplicate_missing_chunks, 1);
        assert_eq!(send_set.duplicate_missing_bytes, 5);
        assert!(send_set.saves_bytes());
        assert_eq!(send_set.placements[0].unique_ordinal, 0);
        assert_eq!(send_set.placements[1].unique_ordinal, 1);
        assert_eq!(send_set.placements[2].unique_ordinal, 0);
        assert_eq!(send_set.unique_chunks[0].logical_ref_count, 2);
    }

    #[test]
    fn dedupe_payload_set_verifies_sender_store_payloads() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"same"[..], &b"unique"[..], &b"same"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);

        let payloads = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        assert_eq!(payloads.unique_payload_count(), 2);
        assert_eq!(payloads.payload_bytes, 10);
        assert!(payloads.saves_bytes());
        assert_eq!(payloads.payloads[0].payload, b"same");
        assert_eq!(payloads.payloads[1].payload, b"unique");
    }

    #[test]
    fn dedupe_payload_set_canonical_parts_round_trip() {
        let repeated = vec![b'a'; 4096];
        let unique = vec![b'b'; 1024];
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
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        let metadata = payload_set.send_set.to_canonical_bytes().expect("metadata");
        let payload_bytes = payload_set
            .to_canonical_payload_bytes()
            .expect("payload bytes");
        let decoded = DeltaDedupPayloadSet::from_canonical_parts(&plan, &metadata, &payload_bytes)
            .expect("decode canonical parts");

        assert_eq!(decoded, payload_set);
        assert_eq!(
            payload_set.compact_wire_bytes().unwrap(),
            payload_set.payload_bytes + u64::try_from(metadata.len()).unwrap()
        );
        assert!(payload_set.compact_wire_bytes().unwrap() < sender.total_size_bytes);
    }

    #[test]
    fn canonical_dedup_parts_package_unique_payloads_once() {
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
        let payload_set = parts.decode_payload_set(&plan).expect("payload set");

        assert_eq!(parts.unique_payload_wire_bytes, 5120);
        assert_eq!(parts.logical_missing_bytes, sender.total_size_bytes);
        assert_eq!(parts.duplicate_missing_chunks, 1);
        assert_eq!(parts.duplicate_missing_bytes, 4096);
        assert_eq!(payload_set.unique_payload_count(), 2);
        assert!(parts.saves_bytes());
        assert_eq!(
            parts.compact_wire_bytes,
            parts.metadata_wire_bytes + parts.unique_payload_wire_bytes
        );
        assert_eq!(
            parts.saved_bytes(),
            sender.total_size_bytes - parts.compact_wire_bytes
        );
        assert_eq!(
            parts
                .compact_wire_bytes_with_outer_overhead(128)
                .expect("wire plus outer overhead"),
            parts.compact_wire_bytes + 128
        );
        assert!(
            parts
                .saves_bytes_with_outer_overhead(128)
                .expect("saves with outer overhead")
        );
        assert_eq!(
            parts
                .saved_bytes_with_outer_overhead(128)
                .expect("saved with overhead"),
            sender.total_size_bytes - parts.compact_wire_bytes - 128
        );
    }

    #[test]
    fn canonical_dedup_parts_if_smaller_accounts_outer_envelope() {
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
        let saved_without_outer = parts.saved_bytes();
        assert!(saved_without_outer > 0);

        let selected = build_canonical_dedup_payload_parts_if_smaller(
            &plan,
            &sender_store,
            saved_without_outer - 1,
        )
        .expect("selected compact parts")
        .expect("compact still saves one byte");
        assert_eq!(selected.metadata_bytes, parts.metadata_bytes);
        assert_eq!(selected.unique_payload_bytes, parts.unique_payload_bytes);

        let rejected = build_canonical_dedup_payload_parts_if_smaller(
            &plan,
            &sender_store,
            saved_without_outer,
        )
        .expect("compact selection");
        assert!(rejected.is_none());
    }

    #[test]
    fn canonical_dedup_parts_reject_accounting_drift() {
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

        let mut bad_metadata_len = parts.clone();
        bad_metadata_len.metadata_wire_bytes += 1;
        assert!(matches!(
            bad_metadata_len.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));

        let mut bad_compact_len = parts.clone();
        bad_compact_len.compact_wire_bytes += 1;
        assert!(matches!(
            bad_compact_len.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));

        let mut bad_logical_bytes = parts.clone();
        bad_logical_bytes.logical_missing_bytes -= 1;
        assert!(matches!(
            bad_logical_bytes.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanWholeBytesMismatch { .. })
        ));

        let mut bad_duplicate_chunks = parts.clone();
        bad_duplicate_chunks.duplicate_missing_chunks += 1;
        assert!(matches!(
            bad_duplicate_chunks.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanItemCountMismatch { .. })
        ));

        let mut bad_duplicate_bytes = parts;
        bad_duplicate_bytes.duplicate_missing_bytes += 1;
        assert!(matches!(
            bad_duplicate_bytes.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));
    }

    #[test]
    fn canonical_dedup_parts_are_stable_across_ingest_runs() {
        let repeated = vec![b'r'; 4096];
        let unique = vec![b'u'; 1024];
        let chunks = [repeated.as_slice(), unique.as_slice(), repeated.as_slice()];

        let mut sender_store_a = ContentAddressedChunkStore::new();
        let mut receiver_store_a = ContentAddressedChunkStore::new();
        let sender_a = manifest(&mut sender_store_a, "tree-a", &chunks);
        let receiver_a = manifest(&mut receiver_store_a, "tree-a", &[]);
        let coverage_a = ReceiverCasCoverage::from_manifest(&receiver_a);
        let plan_a = plan_incremental_resync_with_receiver_coverage(
            &sender_a,
            Some(&receiver_a),
            &coverage_a,
        );
        let parts_a = build_canonical_dedup_payload_parts(&plan_a, &sender_store_a)
            .expect("canonical parts a");

        let mut sender_store_b = ContentAddressedChunkStore::new();
        let mut receiver_store_b = ContentAddressedChunkStore::new();
        let sender_b = manifest(&mut sender_store_b, "tree-a", &chunks);
        let receiver_b = manifest(&mut receiver_store_b, "tree-a", &[]);
        let coverage_b = ReceiverCasCoverage::from_manifest(&receiver_b);
        let plan_b = plan_incremental_resync_with_receiver_coverage(
            &sender_b,
            Some(&receiver_b),
            &coverage_b,
        );
        let parts_b = build_canonical_dedup_payload_parts(&plan_b, &sender_store_b)
            .expect("canonical parts b");

        assert_eq!(sender_a.to_canonical_bytes(), sender_b.to_canonical_bytes());
        assert_eq!(plan_a.missing_chunks, plan_b.missing_chunks);
        assert_eq!(parts_a.metadata_bytes, parts_b.metadata_bytes);
        assert_eq!(parts_a.unique_payload_bytes, parts_b.unique_payload_bytes);
        assert_eq!(parts_a.compact_wire_bytes, parts_b.compact_wire_bytes);
    }

    #[test]
    fn dedupe_payload_set_canonical_parts_fail_closed_on_payload_drift() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(&mut sender_store, "tree-a", &[&b"alpha"[..], &b"beta"[..]]);
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");
        let metadata = payload_set.send_set.to_canonical_bytes().expect("metadata");
        let mut payload_bytes = payload_set
            .to_canonical_payload_bytes()
            .expect("payload bytes");

        payload_bytes[0] ^= 0x40;
        assert!(matches!(
            DeltaDedupPayloadSet::from_canonical_parts(&plan, &metadata, &payload_bytes),
            Err(DeltaError::ChunkPayloadHashMismatch { .. })
        ));
        payload_bytes.pop();
        assert!(matches!(
            DeltaDedupPayloadSet::from_canonical_parts(&plan, &metadata, &payload_bytes),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));
    }

    #[test]
    fn dedupe_payload_set_rejects_reordered_unique_payloads() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"alpha"[..], &b"beta"[..], &b"alpha"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let mut payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        payload_set.payloads.swap(0, 1);

        assert!(matches!(
            payload_set.validate_against_send_set(),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 0 })
        ));
    }

    #[test]
    fn dedupe_send_set_canonical_metadata_round_trips() {
        let repeated = vec![b'x'; 4096];
        let unique = vec![b'y'; 2048];
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
        let send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");

        let encoded = send_set.to_canonical_bytes().expect("encode metadata");
        let decoded =
            DeltaDedupSendSet::from_canonical_bytes(&plan, &encoded).expect("decode metadata");

        assert_eq!(decoded, send_set);
        assert_eq!(encoded.len(), send_set.canonical_metadata_bytes());
        assert_eq!(
            send_set.compact_wire_floor_bytes().unwrap(),
            send_set.unique_payload_bytes + u64::try_from(encoded.len()).unwrap()
        );
        assert!(send_set.compact_wire_floor_bytes().unwrap() < send_set.logical_missing_bytes);
    }

    #[test]
    fn dedupe_send_set_canonical_metadata_rejects_invalid_unique_ordinal() {
        let repeated = vec![b'x'; 4096];
        let unique = vec![b'y'; 2048];
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
        let mut send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");

        send_set.placements[1].unique_ordinal = send_set.unique_chunks.len();
        let encoded = send_set
            .to_canonical_bytes()
            .expect("encode forged metadata");

        assert_eq!(
            DeltaDedupSendSet::from_canonical_bytes(&plan, &encoded),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 1 })
        );
    }

    #[test]
    fn dedupe_send_set_canonical_metadata_fails_closed_on_drift() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"alpha"[..], &b"beta"[..], &b"alpha"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");
        let encoded = send_set.to_canonical_bytes().expect("encode metadata");

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0x80;
        assert_eq!(
            DeltaDedupSendSet::from_canonical_bytes(&plan, &bad_magic).unwrap_err(),
            DeltaError::BadMagic
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            DeltaDedupSendSet::from_canonical_bytes(&plan, &trailing),
            Err(DeltaError::TrailingBytes { trailing: 1 })
        ));

        let mut drifted = send_set.clone();
        drifted.placements[2].unique_ordinal = 1;
        assert!(matches!(
            drifted.validate_against_plan(&plan),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 2 })
        ));
    }
