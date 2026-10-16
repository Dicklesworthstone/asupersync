    use super::*;

    fn ingest_manifest(
        store: &mut ContentAddressedChunkStore,
        tree_id: &str,
        chunks: Vec<&[u8]>,
    ) -> PersistentChunkManifest {
        let ingest = store.ingest_ordered_chunks(chunks).expect("ingest chunks");
        PersistentChunkManifest::new(tree_id, ingest.chunks).expect("manifest")
    }

    fn fixed_chunks(bytes: &[u8], chunk_size: usize) -> Vec<&[u8]> {
        bytes.chunks(chunk_size).collect()
    }

    #[test]
    fn content_addressed_store_deduplicates_repeated_chunks() {
        let mut store = ContentAddressedChunkStore::new();
        let ingest = store
            .ingest_ordered_chunks(vec![
                b"alpha".as_slice(),
                b"beta".as_slice(),
                b"alpha".as_slice(),
            ])
            .expect("ingest");

        assert_eq!(store.unique_chunk_count(), 2);
        assert_eq!(store.unique_bytes(), 9);
        assert_eq!(ingest.store_report.total_chunks, 3);
        assert_eq!(ingest.store_report.inserted_chunks, 2);
        assert_eq!(ingest.store_report.duplicate_chunks, 1);
        assert_eq!(ingest.store_report.inserted_bytes, 9);
        assert_eq!(ingest.store_report.duplicate_bytes, 5);
        assert_eq!(ingest.chunks[0].byte_offset, 0);
        assert_eq!(ingest.chunks[1].byte_offset, 5);
        assert_eq!(ingest.chunks[2].byte_offset, 9);
        assert_eq!(ingest.chunks[0].content_id, ingest.chunks[2].content_id);
    }

    #[test]
    fn manifest_round_trips_canonical_bytes_and_journal_resume_chunks() {
        let mut store = ContentAddressedChunkStore::new();
        let manifest = ingest_manifest(
            &mut store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );

        let decoded = PersistentChunkManifest::from_canonical_bytes(&manifest.to_canonical_bytes())
            .expect("decode");
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.total_size_bytes, 9);
        assert_eq!(decoded.journal_resume_chunks().len(), 2);
        assert_eq!(decoded.journal_resume_chunks()[0].chunk_offset, 0);
        assert_eq!(decoded.journal_resume_chunks()[0].chunk_size, 5);
        assert_eq!(
            decoded.journal_resume_chunks()[0].chunk_hash,
            *decoded.chunks[0].content_id.hash()
        );
        decoded
            .verify_store_coverage(&store)
            .expect("store covers manifest");
    }

    #[test]
    fn manifest_root_changes_when_chunk_content_changes() {
        let mut left_store = ContentAddressedChunkStore::new();
        let mut right_store = ContentAddressedChunkStore::new();
        let left = ingest_manifest(
            &mut left_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let right = ingest_manifest(
            &mut right_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"zeta".as_slice()],
        );

        assert_ne!(left.merkle_root, right.merkle_root);
        assert_ne!(left.to_canonical_bytes(), right.to_canonical_bytes());
    }

    #[test]
    fn manifest_decode_fails_closed_on_root_tamper() {
        let mut store = ContentAddressedChunkStore::new();
        let manifest = ingest_manifest(&mut store, "tree-a", vec![b"alpha".as_slice()]);
        let mut encoded = manifest.to_canonical_bytes();
        let last = encoded.last_mut().expect("root byte");
        *last ^= 0x80;

        let err = PersistentChunkManifest::from_canonical_bytes(&encoded).expect_err("tamper");
        assert!(matches!(err, DeltaError::ManifestRootMismatch { .. }));
    }

    #[test]
    fn manifest_rejects_non_contiguous_layout() {
        let chunk = CasChunkRef {
            index: 1,
            byte_offset: 0,
            size_bytes: 5,
            content_id: ContentId::from_bytes(b"alpha"),
        };

        let err = PersistentChunkManifest::new("tree-a", vec![chunk]).expect_err("bad index");
        assert_eq!(
            err,
            DeltaError::NonContiguousIndex {
                expected: 0,
                actual: 1
            }
        );
    }

    #[test]
    fn manifest_diff_reports_missing_and_stale_chunk_sets() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"beta".as_slice(), b"delta".as_slice()],
        );

        let diff = sender.diff_against(&receiver);

        assert_eq!(diff.shared_chunks, 1);
        assert_eq!(diff.missing_chunks.len(), 2);
        assert_eq!(diff.stale_chunks.len(), 1);
        assert_eq!(diff.missing_bytes, 10);
        assert_eq!(diff.stale_bytes, 5);
        assert_eq!(diff.missing_chunks[0].byte_offset, 0);
        assert_eq!(diff.missing_chunks[1].byte_offset, 9);
    }

    #[test]
    fn resync_planner_falls_back_without_prior_manifest() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver_store = ContentAddressedChunkStore::new();

        let plan = plan_incremental_resync(&sender, None, &receiver_store);

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::NoReceiverManifest)
        );
        assert_eq!(plan.missing_chunks, sender.chunks);
        assert_eq!(plan.missing_bytes, sender.total_size_bytes);
    }

    #[test]
    fn resync_planner_noops_when_manifest_and_cas_match() {
        let mut receiver_store = ContentAddressedChunkStore::new();
        let manifest = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );

        let plan = plan_incremental_resync(&manifest, Some(&manifest), &receiver_store);

        assert_eq!(plan.mode, DeltaResyncMode::AlreadyInSync);
        assert_eq!(plan.fallback_reason, None);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.shared_chunks, 2);
    }

    #[test]
    fn resync_planner_schedules_only_receiver_missing_chunks() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );

        let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);

        assert!(plan.uses_delta_chunks());
        assert_eq!(plan.fallback_reason, None);
        assert_eq!(plan.shared_chunks, 2);
        assert_eq!(plan.missing_chunks.len(), 1);
        assert_eq!(
            plan.missing_chunks[0].content_id,
            ContentId::from_bytes(b"gamma")
        );
        assert_eq!(
            plan.missing_content_ids(),
            vec![ContentId::from_bytes(b"gamma")]
        );
        assert_eq!(plan.missing_bytes, 5);
    }

    #[test]
    fn resync_planner_uses_receiver_cas_even_when_prior_layout_differs() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"old".as_slice()],
        );
        receiver_store
            .insert(b"beta")
            .expect("receiver has beta in CAS");

        let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);

        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.shared_chunks, 2);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.missing_bytes, 0);
        assert_eq!(plan.stale_chunks.len(), 1);
    }

    #[test]
    fn receiver_have_set_advertisement_drives_delta_plan() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            Default::default(),
        )
        .expect("receiver have-set");

        assert_eq!(advertisement.schema, ATP_DELTA_RECEIVER_HAVE_SET_SCHEMA);
        assert_eq!(advertisement.len(), 2);
        assert_eq!(
            advertisement.estimated_wire_bytes(),
            RECEIVER_HAVE_SET_BASE_WIRE_BYTES + 2 * RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES
        );
        assert!(advertisement.describes_manifest(&receiver));

        let plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&receiver),
            Some(&advertisement),
        );

        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.shared_chunks, 2);
        assert_eq!(plan.missing_chunks.len(), 1);
        assert_eq!(
            plan.missing_chunks[0].content_id,
            ContentId::from_bytes(b"gamma")
        );
        assert_eq!(plan.missing_bytes, 5);
    }

    #[test]
    fn receiver_have_set_advertises_extra_verified_cas_for_shifted_layouts() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"old".as_slice()],
        );
        let mut coverage = ReceiverCasCoverage::from_manifest(&receiver);
        coverage.insert(ContentId::from_bytes(b"beta"), 4);

        let advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits::DEFAULT,
        )
        .expect("receiver have-set");
        let plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&receiver),
            Some(&advertisement),
        );

        assert_eq!(advertisement.len(), 3);
        assert_eq!(
            advertisement.estimated_wire_bytes(),
            RECEIVER_HAVE_SET_BASE_WIRE_BYTES + 3 * RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES
        );
        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.shared_chunks, 2);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.missing_bytes, 0);
        assert_eq!(plan.stale_chunks.len(), 1);
    }

    #[test]
    fn receiver_have_set_round_trips_to_sender_coverage() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"old".as_slice()],
        );
        let mut direct_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        direct_coverage.insert(ContentId::from_bytes(b"beta"), 4);

        let advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &direct_coverage,
            ReceiverHaveSetLimits::DEFAULT,
        )
        .expect("receiver have-set");
        let advertised_coverage = advertisement.to_coverage();

        assert_eq!(advertised_coverage.len(), direct_coverage.len());
        assert!(!advertised_coverage.is_empty());
        for chunk in &receiver.chunks {
            assert!(advertised_coverage.contains_chunk(chunk));
        }
        assert!(advertised_coverage.contains_chunk(&sender.chunks[1]));

        let direct_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &direct_coverage,
        );
        let advertised_plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&receiver),
            Some(&advertisement),
        );

        assert_eq!(advertised_plan, direct_plan);
        assert_eq!(advertised_plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(advertised_plan.shared_chunks, 2);
        assert!(advertised_plan.missing_chunks.is_empty());
        assert_eq!(advertised_plan.stale_chunks.len(), 1);
    }

    #[test]
    fn receiver_have_set_fails_closed_without_verified_coverage() {
        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let mut coverage = ReceiverCasCoverage::new();
        coverage.insert_chunk_ref(&receiver.chunks[0]);

        let err = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits::DEFAULT,
        )
        .expect_err("unverified chunk must not be advertised");

        assert_eq!(err, DeltaError::ReceiverHaveSetMissingChunk { index: 1 });
    }

    #[test]
    fn receiver_have_set_enforces_chunk_and_wire_budgets() {
        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);

        let err = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits {
                max_chunks: 1,
                max_wire_bytes: u64::MAX,
            },
        )
        .expect_err("chunk budget must cap advertisement");
        assert_eq!(
            err,
            DeltaError::ReceiverHaveSetTooManyChunks {
                chunks: 2,
                max_chunks: 1,
            }
        );

        let err = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits {
                max_chunks: usize::MAX,
                max_wire_bytes: RECEIVER_HAVE_SET_BASE_WIRE_BYTES,
            },
        )
        .expect_err("wire budget must cap advertisement");
        assert_eq!(
            err,
            DeltaError::ReceiverHaveSetTooManyBytes {
                bytes: RECEIVER_HAVE_SET_BASE_WIRE_BYTES + 2 * RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES,
                max_bytes: RECEIVER_HAVE_SET_BASE_WIRE_BYTES,
            }
        );
    }

    #[test]
    fn stale_receiver_have_set_falls_back_to_full_object() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut old_receiver_store = ContentAddressedChunkStore::new();
        let mut current_receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let old_receiver = ingest_manifest(
            &mut old_receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let current_receiver = ingest_manifest(
            &mut current_receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"delta".as_slice()],
        );
        let old_coverage = ReceiverCasCoverage::from_manifest(&old_receiver);
        let stale_advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &old_receiver,
            &old_coverage,
            Default::default(),
        )
        .expect("old receiver have-set");

        let plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&current_receiver),
            Some(&stale_advertisement),
        );

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete)
        );
        assert_eq!(plan.missing_bytes, sender.total_size_bytes);
    }

    #[test]
    fn resync_planner_falls_back_when_receiver_cas_does_not_cover_prior_manifest() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "tree-a", vec![b"alpha".as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "tree-a", vec![b"alpha".as_slice()]);
        let empty_receiver_store = ContentAddressedChunkStore::new();

        let plan = plan_incremental_resync(&sender, Some(&receiver), &empty_receiver_store);

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete)
        );
    }

    #[test]
    fn resync_planner_falls_back_when_delta_is_not_smaller_than_full_object() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"new-a".as_slice(), b"new-b".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"old-a".as_slice(), b"old-b".as_slice()],
        );

        let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );
        assert_eq!(plan.missing_chunks, sender.chunks);
        assert_eq!(plan.missing_bytes, sender.total_size_bytes);
    }

    #[test]
    fn send_plan_emits_subchunk_ops_and_reconstructs_byte_identical() {
        let old = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 5 + 41) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        for byte in &mut new[24 * 1024..25 * 1024] {
            *byte ^= 0x5a;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "tree-a", vec![new.as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "tree-a", vec![old.as_slice()]);
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(base_plan.missing_bytes, sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.subchunk_count(), 1);
        assert_eq!(send_plan.whole_chunk_count(), 0);
        assert!(send_plan.beats_full_object(sender.total_size_bytes));
        assert!(send_plan.payload_bytes < send_plan.whole_chunk_bytes);

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        assert!(u64::try_from(wire_payload.len()).expect("wire len") < sender.total_size_bytes);
        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let mut tampered_root = wire_payload.clone();
        tampered_root[DELTA_RESYNC_SEND_PLAN_MAGIC.len()] ^= 0x80;
        let err = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &tampered_root)
            .expect_err("root tamper");
        assert!(matches!(
            err,
            DeltaError::DeltaSendPlanSenderRootMismatch { .. }
        ));

        let DeltaResyncSendItem::SubchunkOps { encoded_ops, .. } = &send_plan.items[0] else {
            panic!("expected sub-chunk op stream");
        };
        let decoded_ops = decode_subdelta_ops(encoded_ops).expect("decode op stream");
        assert!(
            decoded_ops
                .iter()
                .any(|op| matches!(op, SubDeltaOp::Literal(_)))
        );

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(rebuilt, new);

        let applied_from_wire =
            apply_delta_resync_wire_payload(&sender, &receiver_store, base_plan, &wire_payload)
                .expect("apply wire payload");
        let rebuilt_from_wire =
            reconstruct_manifest_bytes(&sender, &applied_from_wire).expect("reconstruct wire");
        assert_eq!(rebuilt_from_wire, new);
    }

    #[test]
    fn send_plan_mixes_subchunk_and_whole_chunks_then_reconstructs_byte_identical() {
        let old_a = (0..(64 * 1024))
            .map(|idx| ((idx * 19 + idx / 3 + 7) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new_a = old_a.clone();
        for byte in &mut new_a[31 * 1024..32 * 1024] {
            *byte ^= 0x33;
        }
        let new_b = (0..(24 * 1024))
            .map(|idx| ((idx * 23 + idx / 11 + 5) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![new_a.as_slice(), new_b.as_slice()],
        );
        let receiver = ingest_manifest(&mut receiver_store, "tree-a", vec![old_a.as_slice()]);
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(base_plan.missing_chunks.len(), 2);
        assert_eq!(base_plan.missing_bytes, sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.subchunk_count(), 1);
        assert_eq!(send_plan.whole_chunk_count(), 1);
        assert!(send_plan.payload_bytes < send_plan.whole_chunk_bytes);

        assert!(matches!(
            &send_plan.items[0],
            DeltaResyncSendItem::SubchunkOps { .. }
        ));
        assert!(matches!(
            &send_plan.items[1],
            DeltaResyncSendItem::WholeChunk { .. }
        ));

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply mixed send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(rebuilt, [new_a.as_slice(), new_b.as_slice()].concat());

        let applied_from_wire =
            apply_delta_resync_wire_payload(&sender, &receiver_store, base_plan, &wire_payload)
                .expect("apply mixed wire payload");
        let rebuilt_from_wire =
            reconstruct_manifest_bytes(&sender, &applied_from_wire).expect("reconstruct wire");
        assert_eq!(
            rebuilt_from_wire,
            [new_a.as_slice(), new_b.as_slice()].concat()
        );
    }

    #[test]
    fn send_plan_compacts_appended_whole_chunk_run_then_reconstructs() {
        let base = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 5 + 41) % 251) as u8)
            .collect::<Vec<_>>();
        let append_a = (0..(32 * 1024))
            .map(|idx| ((idx * 23 + idx / 11 + 13) % 253) as u8)
            .collect::<Vec<_>>();
        let append_b = (0..(32 * 1024))
            .map(|idx| ((idx * 29 + idx / 7 + 19) % 251) as u8)
            .collect::<Vec<_>>();
        let append_c = (0..(16 * 1024))
            .map(|idx| ((idx * 31 + idx / 3 + 47) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "append-file",
            vec![
                base.as_slice(),
                append_a.as_slice(),
                append_b.as_slice(),
                append_c.as_slice(),
            ],
        );
        let receiver = ingest_manifest(&mut receiver_store, "append-file", vec![base.as_slice()]);
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(base_plan.shared_chunks, 1);
        assert_eq!(base_plan.missing_chunks.len(), 3);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.whole_chunk_count(), 3);
        assert_eq!(send_plan.subchunk_count(), 0);
        assert_eq!(send_plan.payload_bytes, send_plan.whole_chunk_bytes);

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        let header_bytes = DELTA_RESYNC_SEND_PLAN_MAGIC.len() + 32 + 1 + 32 + 8 + 8 + 8;
        assert_eq!(
            wire_payload[header_bytes], DELTA_SEND_ITEM_WHOLE_CHUNK_RUN,
            "append should use one implicit whole-chunk run"
        );

        let run_overhead = header_bytes + 1 + 8 + 8;
        assert_eq!(
            wire_payload.len(),
            usize::try_from(send_plan.payload_bytes).expect("payload bytes fit") + run_overhead
        );
        let explicit_whole_item_overhead = 1 + ENCODED_CHUNK_BYTES + 8;
        let legacy_whole_wire_len = usize::try_from(send_plan.payload_bytes)
            .expect("payload bytes fit")
            + header_bytes
            + send_plan.items.len() * explicit_whole_item_overhead;
        assert!(
            wire_payload.len() + 128 < legacy_whole_wire_len,
            "implicit append run should remove per-chunk ref/length metadata"
        );

        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let applied = apply_delta_resync_wire_payload_and_reconstruct(
            &sender,
            &receiver_store,
            base_plan,
            &wire_payload,
        )
        .expect("apply append run");
        assert_eq!(
            applied.reconstructed_bytes,
            [
                base.as_slice(),
                append_a.as_slice(),
                append_b.as_slice(),
                append_c.as_slice()
            ]
            .concat()
        );
        assert_eq!(applied.whole_chunk_count, 3);
        assert_eq!(applied.subchunk_count, 0);
    }

    #[test]
    fn send_plan_chooses_best_overlapping_subchunk_base_after_cdc_drift() {
        let wrong_base = (0..(16 * 1024))
            .map(|idx| ((idx * 5 + 91) % 251) as u8)
            .collect::<Vec<_>>();
        let good_base = (0..(64 * 1024))
            .map(|idx| ((idx * 23 + idx / 7 + 11) % 253) as u8)
            .collect::<Vec<_>>();
        let mut target = good_base[..32 * 1024].to_vec();
        for byte in &mut target[12 * 1024..13 * 1024] {
            *byte ^= 0x63;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "edited-file", vec![target.as_slice()]);
        let receiver = ingest_manifest(
            &mut receiver_store,
            "edited-file",
            vec![wrong_base.as_slice(), good_base.as_slice()],
        );
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            base_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.subchunk_count(), 1);
        assert_eq!(send_plan.whole_chunk_count(), 0);
        assert!(send_plan.payload_bytes < send_plan.whole_chunk_bytes / 4);
        let DeltaResyncSendItem::SubchunkOps { base_chunk, .. } = &send_plan.items[0] else {
            panic!("expected subchunk ops");
        };
        assert_eq!(
            base_chunk.content_id, receiver.chunks[1].content_id,
            "sender should choose the compact overlapping base, not the poor same-index base"
        );

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(rebuilt, target);
    }

    #[test]
    fn send_plan_dedupes_repeated_missing_chunks_then_reconstructs() {
        let repeated = (0..(8 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 43) % 251) as u8)
            .collect::<Vec<_>>();
        let unique = (0..(2 * 1024))
            .map(|idx| ((idx * 11 + idx / 3 + 97) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "repeated-file",
            vec![repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = ingest_manifest(&mut receiver_store, "repeated-file", Vec::new());
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.missing_chunks.len(), 3);
        assert_eq!(base_plan.missing_bytes, sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.whole_chunk_count(), 2);
        assert_eq!(send_plan.subchunk_count(), 0);
        assert_eq!(
            send_plan.payload_bytes,
            u64::try_from(repeated.len() + unique.len()).expect("payload len")
        );
        assert!(matches!(
            send_plan.items[2],
            DeltaResyncSendItem::RepeatedChunk {
                source_ordinal: 0,
                ..
            }
        ));

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        assert!(
            u64::try_from(wire_payload.len()).expect("wire len")
                < sender.total_size_bytes - u64::try_from(repeated.len()).expect("repeat len") / 2
        );
        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(
            rebuilt,
            [repeated.as_slice(), unique.as_slice(), repeated.as_slice()].concat()
        );

        let applied_from_wire =
            apply_delta_resync_wire_payload(&sender, &receiver_store, base_plan, &wire_payload)
                .expect("apply wire payload");
        let rebuilt_from_wire =
            reconstruct_manifest_bytes(&sender, &applied_from_wire).expect("reconstruct wire");
        assert_eq!(rebuilt_from_wire, rebuilt);
    }

    #[test]
    fn send_plan_rejects_repeated_chunk_source_ordinal_forgery() {
        let repeated = (0..(8 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 43) % 251) as u8)
            .collect::<Vec<_>>();
        let unique = (0..(2 * 1024))
            .map(|idx| ((idx * 11 + idx / 3 + 97) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "repeated-file",
            vec![repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = ingest_manifest(&mut receiver_store, "repeated-file", Vec::new());
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );
        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        let DeltaResyncSendItem::RepeatedChunk {
            chunk,
            source_ordinal,
        } = &send_plan.items[2]
        else {
            panic!("expected compacted repeated chunk");
        };
        assert_eq!(*source_ordinal, 0);

        let mut self_referential = send_plan.clone();
        self_referential.items[2] = DeltaResyncSendItem::RepeatedChunk {
            chunk: chunk.clone(),
            source_ordinal: 2,
        };
        assert!(matches!(
            self_referential.to_wire_bytes(),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 2 })
        ));

        let mut wrong_source = send_plan.clone();
        wrong_source.items[2] = DeltaResyncSendItem::RepeatedChunk {
            chunk: chunk.clone(),
            source_ordinal: 1,
        };
        assert!(matches!(
            wrong_source.to_wire_bytes(),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 2 })
        ));
    }

    #[test]
    fn wire_payload_report_transmits_delta_and_reconstructs_bench_object() {
        let shared = (0..(32 * 1024))
            .map(|idx| ((idx * 13 + 11) % 251) as u8)
            .collect::<Vec<_>>();
        let old_changed = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 7 + 3) % 253) as u8)
            .collect::<Vec<_>>();
        let mut new_changed = old_changed.clone();
        for byte in &mut new_changed[28 * 1024..29 * 1024] {
            *byte ^= 0x71;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "bench-file",
            vec![shared.as_slice(), new_changed.as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "bench-file",
            vec![shared.as_slice(), old_changed.as_slice()],
        );
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(base_plan.shared_chunks, 1);
        assert_eq!(base_plan.missing_chunks.len(), 1);
        assert_eq!(
            base_plan.missing_bytes,
            u64::try_from(new_changed.len()).expect("test chunk len")
        );

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let payload =
            build_delta_resync_wire_payload(&base_plan, &sender_store, &receiver, &signatures)
                .expect("wire payload");

        assert_eq!(payload.base_plan, base_plan);
        assert_eq!(payload.subchunk_count, 1);
        assert_eq!(payload.whole_chunk_count, 0);
        assert!(payload.payload_bytes < payload.whole_chunk_bytes);
        assert!(payload.beats_full_object(sender.total_size_bytes));

        let applied = apply_delta_resync_wire_payload_and_reconstruct(
            &sender,
            &receiver_store,
            payload.base_plan.clone(),
            &payload.wire_payload,
        )
        .expect("apply and reconstruct");

        assert_eq!(applied.wire_payload_bytes, payload.wire_payload_bytes);
        assert_eq!(applied.payload_bytes, payload.payload_bytes);
        assert_eq!(applied.whole_chunk_bytes, payload.whole_chunk_bytes);
        assert_eq!(applied.subchunk_count, 1);
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(
            applied.reconstructed_bytes,
            [shared.as_slice(), new_changed.as_slice()].concat()
        );
        sender
            .verify_store_coverage(&applied.store)
            .expect("target coverage");
    }

    #[test]
    fn wire_apply_report_rejects_payload_accounting_mismatch() {
        let shared = (0..(32 * 1024))
            .map(|idx| ((idx * 7 + 19) % 251) as u8)
            .collect::<Vec<_>>();
        let old_changed = (0..(64 * 1024))
            .map(|idx| ((idx * 29 + idx / 13 + 17) % 253) as u8)
            .collect::<Vec<_>>();
        let mut new_changed = old_changed.clone();
        for byte in &mut new_changed[20 * 1024..21 * 1024] {
            *byte ^= 0x4d;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "bench-file",
            vec![shared.as_slice(), new_changed.as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "bench-file",
            vec![shared.as_slice(), old_changed.as_slice()],
        );
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );
        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let payload =
            build_delta_resync_wire_payload(&base_plan, &sender_store, &receiver, &signatures)
                .expect("wire payload");

        let mut tampered = payload.wire_payload.clone();
        let receiver_root_bytes = if payload.base_plan.receiver_merkle_root.is_some() {
            32
        } else {
            0
        };
        let payload_bytes_offset =
            DELTA_RESYNC_SEND_PLAN_MAGIC.len() + 32 + 1 + receiver_root_bytes + 8;
        tampered[payload_bytes_offset + 7] ^= 0x01;

        let err = apply_delta_resync_wire_payload_and_reconstruct(
            &sender,
            &receiver_store,
            payload.base_plan,
            &tampered,
        )
        .expect_err("payload accounting mismatch must fail closed");
        assert!(matches!(
            err,
            DeltaError::DeltaSendPlanPayloadBytesMismatch { .. }
        ));
    }

    #[test]
    fn transmission_falls_back_when_delta_envelope_exceeds_full_object() {
        let shared = vec![0x11, 0x22];
        let mut sender_chunks = Vec::new();
        sender_chunks.push(shared.clone());
        for idx in 0..512u16 {
            sender_chunks.push(vec![(idx & 0xff) as u8, (idx >> 8) as u8, 0xa5]);
        }
        let sender_slices = sender_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "tiny-chunk-file", sender_slices);
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tiny-chunk-file",
            vec![shared.as_slice()],
        );

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::DeltaChunks);
        assert!(chunk_level_plan.missing_bytes < sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let raw_delta = build_delta_resync_wire_payload(
            &chunk_level_plan,
            &sender_store,
            &receiver,
            &signatures,
        )
        .expect("raw delta wire payload");
        assert!(
            raw_delta.wire_payload_bytes > sender.total_size_bytes,
            "test fixture must exercise metadata-dominated over-full delta"
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.requires_full_object_fallback());
        assert_eq!(
            transmission.plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );
        assert!(transmission.wire_payload.is_none());
    }

    #[test]
    fn transmission_promotes_sparse_edited_file_to_delta_wire_payload() {
        let old = (0..(96 * 1024))
            .map(|idx| ((idx * 29 + idx / 5 + 97) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        for byte in &mut new[44 * 1024..45 * 1024] {
            *byte ^= 0xa6;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "edited-file", vec![new.as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "edited-file", vec![old.as_slice()]);

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            chunk_level_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.uses_delta_wire_payload());
        assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(transmission.plan.fallback_reason, None);
        let wire_payload = transmission
            .wire_payload
            .as_ref()
            .expect("delta wire payload");
        assert_eq!(wire_payload.subchunk_count, 1);
        assert_eq!(wire_payload.whole_chunk_count, 0);
        assert!(wire_payload.payload_bytes < wire_payload.whole_chunk_bytes);
        assert!(wire_payload.wire_payload_bytes < sender.total_size_bytes / 4);

        let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
            .expect("apply transmission")
            .expect("delta apply report");

        assert_eq!(applied.reconstructed_bytes, new);
        assert_eq!(applied.subchunk_count, 1);
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
    }

    #[test]
    fn transmission_promotes_scattered_byte_flips_to_delta_wire_payload() {
        let old = (0..(512 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 17) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        let scattered_edits = old.len() / 100;
        for edit in 0..scattered_edits {
            let pos = (edit * 7919 + 104_729) % new.len();
            new[pos] ^= 0xa5;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "scattered-file", vec![new.as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "scattered-file", vec![old.as_slice()]);

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            chunk_level_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.uses_delta_wire_payload());
        assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(transmission.plan.fallback_reason, None);
        let wire_payload = transmission
            .wire_payload
            .as_ref()
            .expect("delta wire payload");
        assert_eq!(wire_payload.subchunk_count, 1);
        assert_eq!(wire_payload.whole_chunk_count, 0);
        assert!(wire_payload.beats_full_object(sender.total_size_bytes));
        assert!(wire_payload.wire_payload_bytes < sender.total_size_bytes * 3 / 4);

        let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
            .expect("apply transmission")
            .expect("delta apply report");

        assert_eq!(applied.reconstructed_bytes, new);
        assert_eq!(applied.subchunk_count, 1);
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
    }

    #[test]
    fn transmission_keeps_scattered_multichunk_edits_on_delta_wire_path() {
        let chunk_size = 64 * 1024;
        let old = (0..(8 * chunk_size))
            .map(|idx| ((idx * 37 + idx / 11 + 53) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        let scattered_edits = old.len() / 100;
        for edit in 0..scattered_edits {
            let pos = (edit * 7919 + 104_729) % new.len();
            new[pos] ^= 0xa5;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "scattered-multichunk-file",
            fixed_chunks(&new, chunk_size),
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "scattered-multichunk-file",
            fixed_chunks(&old, chunk_size),
        );

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            chunk_level_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.uses_delta_wire_payload());
        assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(transmission.plan.fallback_reason, None);
        let wire_payload = transmission
            .wire_payload
            .as_ref()
            .expect("delta wire payload");
        assert_eq!(wire_payload.subchunk_count, sender.chunks.len());
        assert_eq!(wire_payload.whole_chunk_count, 0);
        assert!(wire_payload.beats_full_object(sender.total_size_bytes));

        let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
            .expect("apply transmission")
            .expect("delta apply report");

        assert_eq!(applied.reconstructed_bytes, new);
        assert_eq!(applied.subchunk_count, sender.chunks.len());
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
    }

    #[test]
    fn test_reconstruct_manifest_bytes_fails_closed_before_allocating() {
        let mut store = ContentAddressedChunkStore::new();
        let payload = b"correct payload chunk";
        let manifest = ingest_manifest(&mut store, "test-reconstruct", vec![payload]);

        let empty_store = ContentAddressedChunkStore::new();
        let err = reconstruct_manifest_bytes(&manifest, &empty_store).unwrap_err();
        assert!(matches!(err, DeltaError::MissingChunk { index: 0, .. }));

        // Corrupted payload size in store
        let mut corrupt_size_store = ContentAddressedChunkStore::new();
        corrupt_size_store
            .chunks
            .insert(manifest.chunks[0].content_id.clone(), b"wrong".to_vec());
        let err = reconstruct_manifest_bytes(&manifest, &corrupt_size_store).unwrap_err();
        assert!(matches!(
            err,
            DeltaError::ChunkPayloadSizeMismatch { index: 0, .. }
        ));
    }

    #[test]
    fn test_apply_delta_resync_send_plan_rejects_whole_chunk_mismatch_without_polluting_store() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-whole-chunk-check",
            vec![b"original chunk payload content"],
        );
        let receiver_store = ContentAddressedChunkStore::new();
        let target_chunk = sender.chunks[0].clone();

        // 1. Size mismatch
        let mut plan = DeltaResyncSendPlan {
            base_plan: plan_incremental_resync(&sender, None, &receiver_store),
            items: vec![DeltaResyncSendItem::WholeChunk {
                chunk: target_chunk.clone(),
                payload: b"short".to_vec(),
            }],
            payload_bytes: 5,
            whole_chunk_bytes: 5,
        };
        let err = apply_delta_resync_send_plan(&sender, &receiver_store, &plan).unwrap_err();
        assert!(matches!(
            err,
            DeltaError::ChunkPayloadSizeMismatch { index: 0, .. }
        ));

        // 2. Hash mismatch (same size, wrong bytes)
        let wrong_payload = vec![0x7f; target_chunk.size_bytes as usize];
        let wrong_id = ContentId::from_bytes(&wrong_payload);
        plan.items = vec![DeltaResyncSendItem::WholeChunk {
            chunk: target_chunk,
            payload: wrong_payload,
        }];
        let err = apply_delta_resync_send_plan(&sender, &receiver_store, &plan).unwrap_err();
        assert!(matches!(
            err,
            DeltaError::ChunkPayloadHashMismatch { index: 0, .. }
        ));
        assert!(!receiver_store.contains(&wrong_id));
    }

    #[test]
    fn test_subchunk_planning_framing_overhead_prefers_whole_chunk() {
        let target_payload = (0..256)
            .map(|idx| ((idx * 11 + idx / 7 + 13) % 251) as u8)
            .collect::<Vec<_>>();
        let base_payload = target_payload.clone();

        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = ingest_manifest(
            &mut receiver_store,
            "framing-overhead",
            vec![&base_payload],
        );
        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");

        // Target chunk where diff saves fewer than SUBDELTA_FRAMING_OVERHEAD_BYTES (84 bytes)
        // With an 80-byte target, whole chunk is 61 + 80 = 141 bytes,
        // whereas subchunk ops wire framing alone is 145 bytes.
        let small_target = (0..80)
            .map(|idx| ((idx * 13 + idx / 5 + 17) % 251) as u8)
            .collect::<Vec<_>>();
        let small_chunk = CasChunkRef::from_bytes(0, 0, &small_target).expect("chunk ref");
        let item = build_delta_resync_send_item(&small_chunk, &small_target, &receiver, &signatures)
            .expect("build send item");
        assert!(
            matches!(item, DeltaResyncSendItem::WholeChunk { .. }),
            "expected WholeChunk due to 84-byte subdelta framing overhead"
        );
    }

    #[test]
    fn test_content_addressed_chunk_store_contains_and_coverage() {
        let mut store = ContentAddressedChunkStore::new();
        let payload = b"hello test payload";
        let content_id = ContentId::from_bytes(payload);

        assert!(!store.contains(&content_id));
        assert!(!store.contains_coverage(&content_id));

        // Insert verified coverage only (no chunk payload stored)
        store.insert_verified_coverage(content_id.clone(), payload.len() as u64);
        assert!(!store.contains(&content_id));
        assert!(store.contains_coverage(&content_id));

        // Insert actual payload
        store.insert(payload).expect("insert payload");
        assert!(store.contains(&content_id));
        assert!(store.contains_coverage(&content_id));
    }
