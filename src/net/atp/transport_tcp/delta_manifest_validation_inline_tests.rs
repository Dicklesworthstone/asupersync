    use super::*;
    use crate::net::atp::transport_common::DeltaChunkWire;
    use super::super::ManifestEntry;

    fn fixture(size: u64) -> (TransferManifest, DeltaManifestWire) {
        let entry = ManifestEntry {
            index: 0,
            rel_path: "payload".into(),
            size,
            sha256_hex: "00".repeat(32),
            metadata: None,
            members: Vec::new(),
        };
        let delta = DeltaManifestWire {
            schema: "schema".into(),
            tree_id: "tree".into(),
            chunk_size: 4096,
            total_size_bytes: size,
            merkle_root_hex: "11".repeat(32),
            chunks: if size == 0 {
                Vec::new()
            } else {
                vec![DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "payload".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: size,
                    content_id_hex: "22".repeat(32),
                }]
            },
        };
        (
            TransferManifest {
                transfer_id: "t".into(),
                root_name: "r".into(),
                is_directory: false,
                total_bytes: size,
                merkle_root_hex: "33".repeat(32),
                metadata_root_hex: None,
                directory_metadata: None,
                entries: vec![entry],
                delta_manifest: Some(delta.clone()),
            },
            delta,
        )
    }

    #[test]
    fn accepts_complete_bounded_layout() {
        let (manifest, delta) = fixture(1024);
        validate(&manifest, &delta).unwrap();
        let (manifest, delta) = fixture(0);
        validate(&manifest, &delta).unwrap();
    }

    #[test]
    fn rejects_unbounded_chunk_size_before_baseline_reads() {
        let (manifest, mut delta) = fixture(1);
        delta.chunk_size = usize::try_from(MAX_COMPRESSED_CHUNK_RAW).unwrap() + 1;
        assert!(validate(&manifest, &delta).is_err());
        delta.chunk_size = 0;
        assert!(validate(&manifest, &delta).is_err());
    }

    #[test]
    fn rejects_path_index_and_extent_mismatches() {
        let (manifest, delta) = fixture(10);
        for mutate in 0..4 {
            let mut bad = delta.clone();
            match mutate {
                0 => bad.chunks[0].entry_index = 7,
                1 => bad.chunks[0].rel_path = "other".into(),
                2 => bad.chunks[0].entry_offset = 1,
                _ => bad.chunks[0].size_bytes = 11,
            }
            assert!(validate(&manifest, &bad).is_err(), "case {mutate}");
        }
    }

    #[test]
    fn rejects_partial_coverage_and_transfer_total_mismatch() {
        let (manifest, mut delta) = fixture(10);
        delta.chunks[0].size_bytes = 9;
        assert!(validate(&manifest, &delta).is_err());

        let (manifest, mut delta) = fixture(10);
        delta.total_size_bytes = 9;
        assert!(validate(&manifest, &delta).is_err());
    }

    #[test]
    fn rejects_content_for_metadata_only_entries() {
        let (mut manifest, delta) = fixture(10);
        manifest.entries[0].metadata = Some(EntryMetadata {
            file_kind: FileKind::Directory,
            ..EntryMetadata::default()
        });
        assert!(validate(&manifest, &delta).is_err());
    }
