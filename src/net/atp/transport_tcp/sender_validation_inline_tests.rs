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
