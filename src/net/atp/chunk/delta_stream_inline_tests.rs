    use super::*;

    fn chunk(bytes: &[u8]) -> DeltaChunkPayload {
        DeltaChunkPayload::from_bytes(bytes.to_vec())
    }

    fn cas_chunk(path: &str, offset: u64, bytes: &[u8]) -> CasManifestChunk {
        CasManifestChunk {
            rel_path: path.to_string(),
            byte_offset: offset,
            address: ChunkAddress::from_bytes(bytes),
        }
    }

    #[test]
    fn missing_chunks_pack_into_one_coalesced_delta_object() {
        let a = chunk(b"alpha");
        let b = chunk(b"beta");
        let extra = chunk(b"extra");
        let requested = BTreeSet::from([a.fingerprint, b.fingerprint]);

        let plan = plan_delta_raptorq_stream(
            &requested,
            [extra, b.clone(), a.clone()],
            &DeltaRaptorQConfig {
                symbol_size: 256,
                max_object_payload_bytes: 4096,
                repair_overhead_percent: 25,
            },
        )
        .expect("delta plan should build");

        assert_eq!(plan.objects.len(), 1);
        let expected_order = requested.iter().copied().collect::<Vec<_>>();
        assert_eq!(plan.objects[0].chunk_fingerprints, expected_order);
        assert_eq!(
            plan.total_delta_payload_bytes(),
            plan.objects[0].payload_len
        );
        assert_eq!(plan.total_source_symbols(), 1);
        assert_eq!(plan.total_repair_symbol_budget(), 1);
        assert!(plan.objects[0].source_symbols[0].descriptor.is_source);
    }

    #[test]
    fn absent_requested_chunk_fails_closed() {
        let a = chunk(b"alpha");
        let missing = chunk(b"missing");
        let requested = BTreeSet::from([a.fingerprint, missing.fingerprint]);

        let result = plan_delta_raptorq_stream(&requested, [a], &DeltaRaptorQConfig::default());

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("not available")
        ));
    }

    #[test]
    fn cdc_payload_constructor_rejects_hash_mismatch() {
        let chunk = CdcChunkData {
            byte_offset: 0,
            size_bytes: 5,
            content_hash: sha256(b"alpha"),
        };

        let result = DeltaChunkPayload::from_cdc_chunk(&chunk, b"bravo".to_vec());

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("hash mismatch")
        ));
    }

    #[test]
    fn decoded_delta_object_payload_round_trips_and_rejects_corruption() {
        let a = chunk(b"alpha");
        let b = chunk(b"beta");
        let requested = BTreeSet::from([a.fingerprint, b.fingerprint]);
        let plan = plan_delta_raptorq_stream(
            &requested,
            [a.clone(), b.clone()],
            &DeltaRaptorQConfig {
                symbol_size: 256,
                max_object_payload_bytes: 4096,
                repair_overhead_percent: 20,
            },
        )
        .expect("delta plan");
        let object = &plan.objects[0];
        let mut payload = Vec::new();
        for symbol in &object.source_symbols {
            payload.extend_from_slice(&symbol.payload);
        }
        payload.truncate(object.payload_len);

        let decoded = decode_delta_object_payload(&payload).expect("decoded payload");
        let decoded_fingerprints = decoded
            .iter()
            .map(|chunk| chunk.fingerprint)
            .collect::<BTreeSet<_>>();
        assert_eq!(decoded_fingerprints, requested);

        let last = payload.last_mut().expect("payload byte");
        *last ^= 0xff;
        assert!(matches!(
            decode_delta_object_payload(&payload),
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("hash mismatch")
        ));
    }

    #[test]
    fn reassembly_commits_cas_and_decoded_chunks_after_full_verification() {
        let expected_files = BTreeMap::from([
            ("a.txt".to_string(), b"alpha-bravo".to_vec()),
            ("b.txt".to_string(), b"charlie".to_vec()),
        ]);
        let manifest = CasMerkleManifest::from_chunks(
            "tree",
            [
                cas_chunk("a.txt", 0, b"alpha-"),
                cas_chunk("a.txt", 6, b"bravo"),
                cas_chunk("b.txt", 0, b"charlie"),
            ],
        )
        .expect("manifest");
        let expectation =
            DeltaReassemblyExpectation::from_manifest_and_files(&manifest, &expected_files);
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(b"alpha-", None).expect("cas alpha");
        cas.insert_chunk(b"charlie", None).expect("cas charlie");
        let mut destination = BTreeMap::from([("a.txt".to_string(), b"old".to_vec())]);

        let receipt = verify_and_commit_delta_reassembly(
            &manifest,
            &cas,
            [DeltaChunkPayload::from_bytes(b"bravo".to_vec())],
            expectation,
            &mut destination,
        )
        .expect("verified commit");

        assert!(receipt.committed);
        assert_eq!(receipt.manifest_root, manifest.root());
        assert_eq!(destination, expected_files);
    }

    #[test]
    fn reassembly_fails_closed_without_mutating_destination() {
        let expected_files = BTreeMap::from([("a.txt".to_string(), b"alpha".to_vec())]);
        let manifest = CasMerkleManifest::from_chunks("tree", [cas_chunk("a.txt", 0, b"alpha")])
            .expect("manifest");
        let expectation =
            DeltaReassemblyExpectation::from_manifest_and_files(&manifest, &expected_files);
        let cas = ContentAddressedChunkStore::new();
        let mut destination = BTreeMap::from([("a.txt".to_string(), b"old".to_vec())]);

        let missing = verify_and_commit_delta_reassembly(
            &manifest,
            &cas,
            Vec::new(),
            expectation,
            &mut destination,
        );
        assert!(matches!(
            missing,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("missing chunk")
        ));
        assert_eq!(destination["a.txt"], b"old".to_vec());

        let corrupt = DeltaChunkPayload {
            fingerprint: ChunkFingerprint::new(sha256(b"alpha")),
            bytes: b"bravo".to_vec(),
        };
        let corrupt_result = verify_and_commit_delta_reassembly(
            &manifest,
            &cas,
            [corrupt],
            expectation,
            &mut destination,
        );
        assert!(matches!(
            corrupt_result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("do not match fingerprint")
        ));
        assert_eq!(destination["a.txt"], b"old".to_vec());
    }
