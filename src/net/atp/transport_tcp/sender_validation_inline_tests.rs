    use super::*;
    use crate::net::atp::transport_common::{DeltaManifestWire, DeltaObjectRequest};

    fn manifest(with_delta: bool) -> TransferManifest {
        TransferManifest {
            transfer_id: "t".into(),
            root_name: "r".into(),
            is_directory: true,
            total_bytes: 0,
            merkle_root_hex: "11".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            entries: Vec::new(),
            delta_manifest: with_delta.then(|| DeltaManifestWire {
                schema: "schema".into(),
                tree_id: "tree".into(),
                chunk_size: 4096,
                total_size_bytes: 0,
                merkle_root_hex: "22".repeat(32),
                chunks: Vec::new(),
            }),
        }
    }

    fn full_request(manifest: &TransferManifest) -> DeltaObjectRequest {
        DeltaObjectRequest::full(
            manifest
                .delta_manifest
                .as_ref()
                .map_or("", |delta| delta.merkle_root_hex.as_str()),
            None,
            "fallback",
        )
    }

    fn receipt() -> ReceiveReceipt {
        ReceiveReceipt {
            committed: true,
            bytes_received: 0,
            files: 0,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            decode_count: 0,
            decode_micros: 0,
            reason: None,
            committed_paths: Vec::new(),
        }
    }

    #[test]
    fn sender_chunk_size_is_bounded_by_raw_frame_capacity() {
        let mut config = TransferConfig::default();
        validate_config(&config).unwrap();
        config.chunk_size = 0;
        assert!(validate_config(&config).is_err());
        config.chunk_size = usize::try_from(MAX_FRAME_SIZE).unwrap();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn request_root_is_bound_to_sent_delta_manifest() {
        for with_delta in [false, true] {
            let manifest = manifest(with_delta);
            let request = full_request(&manifest);
            validate_request(&manifest, &request).unwrap();
            let mut wrong = request;
            wrong.sender_merkle_root_hex = "ff".repeat(32);
            assert!(validate_request(&manifest, &wrong).is_err());
        }
    }

    #[test]
    fn noop_requires_matching_roots_and_no_missing_data() {
        let manifest = manifest(true);
        let mut request = full_request(&manifest);
        request.mode = DeltaWireMode::AlreadyInSync;
        request.receiver_merkle_root_hex = Some(request.sender_merkle_root_hex.clone());
        validate_request(&manifest, &request).unwrap();

        request.missing_bytes = 1;
        assert!(validate_request(&manifest, &request).is_err());
    }

    #[test]
    fn full_mode_rejects_range_instructions() {
        let manifest = manifest(true);
        let mut request = full_request(&manifest);
        request.missing_chunks.push(
            manifest
                .delta_manifest
                .as_ref()
                .and_then(|delta| delta.chunks.first())
                .cloned()
                .unwrap_or_else(|| crate::net::atp::transport_common::DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "x".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: 1,
                    content_id_hex: "00".repeat(32),
                }),
        );
        assert!(validate_request(&manifest, &request).is_err());
    }

    #[test]
    fn receipt_requires_integrity_flags_and_exact_counts() {
        let manifest = manifest(false);
        validate_receipt(&manifest, 0, &receipt()).unwrap();

        let mut bad = receipt();
        bad.sha_ok = false;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());

        let mut bad = receipt();
        bad.bytes_received = 1;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());

        let mut bad = receipt();
        bad.files = 1;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());
    }

    #[test]
    fn negative_receipt_preserves_peer_reason() {
        let manifest = manifest(false);
        let mut bad = receipt();
        bad.committed = false;
        bad.reason = Some("per-entry SHA-256 mismatch".into());
        assert!(matches!(
            validate_receipt(&manifest, 0, &bad),
            Err(TransportError::Integrity(message))
                if message == "per-entry SHA-256 mismatch"
        ));
    }

    fn delta_fixture() -> (TransferManifest, DeltaObjectRequest) {
        use crate::atp::object::ContentId;
        use crate::net::atp::transport_common::DeltaChunkWire;
        use crate::net::atp::transport_tcp::ManifestEntry;

        let mut manifest = manifest(true);
        manifest.total_bytes = 6;
        manifest.entries.push(ManifestEntry {
            index: 0,
            rel_path: "x".into(),
            size: 6,
            sha256_hex: "33".repeat(32),
            metadata: None,
            members: Vec::new(),
        });
        let delta = manifest.delta_manifest.as_mut().unwrap();
        delta.total_size_bytes = 6;
        // The same content occurs at two distinct locations. Both locations
        // cost bytes when requested; content deduplication must not undercount.
        delta.chunks = (0_u32..2)
            .map(|index| DeltaChunkWire {
                index,
                entry_index: 0,
                rel_path: "x".into(),
                entry_offset: u64::from(index) * 3,
                stream_offset: u64::from(index) * 3,
                size_bytes: 3,
                content_id_hex: ContentId::from_bytes(b"abc").to_hex(),
            })
            .collect();
        let mut request = full_request(&manifest);
        request.mode = DeltaWireMode::DeltaChunks;
        request.missing_chunks = manifest.delta_manifest.as_ref().unwrap().chunks.clone();
        request.missing_bytes = 6;
        (manifest, request)
    }

    #[test]
    fn delta_byte_count_matches_locations_not_unique_content_ids() {
        let (manifest, request) = delta_fixture();
        validate_request(&manifest, &request).unwrap();
        let mut reversed = request.clone();
        reversed.missing_chunks.reverse();
        validate_request(&manifest, &reversed).unwrap();

        let mut subset = request;
        subset.missing_chunks.truncate(1);
        subset.missing_bytes = 3;
        validate_request(&manifest, &subset).unwrap();
        // No payload can be legitimate when all chunks can be reused at new
        // locations. This is not the AlreadyInSync mode or a fabricated count.
        subset.missing_chunks.clear();
        subset.missing_bytes = 0;
        validate_request(&manifest, &subset).unwrap();
    }

    #[test]
    fn fabricated_missing_bytes_cannot_be_repeated_as_a_successful_receipt() {
        let (manifest, request) = delta_fixture();
        for claimed in [0, 1, 3, 5, 7, u64::MAX] {
            let mut forged = request.clone();
            forged.missing_bytes = claimed;
            let mut proof = receipt();
            proof.files = 1;
            proof.bytes_received = claimed;
            // Previously the send loop returned this peer-selected number,
            // allowing the receipt to "confirm" it. The receipt alone cannot
            // expose that circular comparison; negotiation must refuse first.
            validate_receipt(&manifest, claimed, &proof).unwrap();
            assert!(matches!(
                validate_request(&manifest, &forged),
                Err(TransportError::Frame(message))
                    if message == format!(
                        "delta ObjectRequest declares {claimed} missing bytes but requests 6"
                    )
            ));
        }
    }

    #[test]
    fn delta_byte_sum_overflow_fails_instead_of_saturating_or_wrapping() {
        let (manifest, mut request) = delta_fixture();
        request.missing_chunks[0].size_bytes = u64::MAX;
        request.missing_chunks[1].size_bytes = 1;
        for claimed in [0, u64::MAX] {
            request.missing_bytes = claimed;
            assert!(matches!(
                validate_request(&manifest, &request),
                Err(TransportError::Frame(message))
                    if message == "delta ObjectRequest byte count overflows u64"
            ));
        }
    }

    #[test]
    fn complete_delta_descriptors_are_bound_to_the_advertised_manifest() {
        let (manifest, request) = delta_fixture();
        for field in 0..7 {
            let mut altered = request.clone();
            let chunk = &mut altered.missing_chunks[0];
            match field {
                0 => chunk.index = 19,
                1 => chunk.entry_index = 1,
                2 => chunk.rel_path = "other".into(),
                3 => chunk.entry_offset = 1,
                4 => chunk.stream_offset = 1,
                5 => {
                    chunk.size_bytes = 2;
                    altered.missing_bytes = 5;
                }
                6 => chunk.content_id_hex = "44".repeat(32),
                _ => unreachable!(),
            }
            assert!(matches!(
                validate_request(&manifest, &altered),
                Err(TransportError::Frame(message))
                    if message == "delta ObjectRequest asks for a chunk outside the sender manifest"
            ));
        }
    }

    #[test]
    fn duplicate_delta_locations_are_refused_even_with_matching_byte_totals() {
        let (manifest, mut request) = delta_fixture();
        request.missing_chunks[1] = request.missing_chunks[0].clone();
        assert!(matches!(
            validate_request(&manifest, &request),
            Err(TransportError::Frame(message))
                if message == "delta ObjectRequest contains duplicate missing chunks"
        ));
    }

    #[test]
    fn excessive_delta_chunk_count_is_refused_before_set_allocation() {
        let (manifest, mut request) = delta_fixture();
        request.missing_chunks.push(request.missing_chunks[0].clone());
        request.missing_bytes = 9;
        assert!(matches!(
            validate_request(&manifest, &request),
            Err(TransportError::Frame(message))
                if message == "delta ObjectRequest contains more chunks than the sender manifest"
        ));
    }
