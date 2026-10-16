    use super::*;

    #[test]
    fn cas_round_trips_and_reports_dedup_hit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let first = store.put_chunk(b"alpha chunk").expect("first insert");
        assert!(first.inserted);
        assert!(
            store
                .has_chunk(first.id, first.size_bytes)
                .expect("has chunk")
        );

        let second = store.put_chunk(b"alpha chunk").expect("dedup insert");
        assert_eq!(second.id, first.id);
        assert!(!second.inserted);
        assert_eq!(
            store
                .get_chunk(first.id, first.size_bytes)
                .expect("get chunk")
                .expect("present"),
            b"alpha chunk"
        );
    }

    #[test]
    fn cdc_chunk_store_fails_closed_on_hash_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let cdc = CdcChunkData {
            byte_offset: 0,
            size_bytes: 4,
            content_hash: DeltaChunkId::from_bytes(b"good").as_bytes(),
        };

        let err = store
            .put_cdc_chunk(&cdc, b"evil")
            .expect_err("wrong bytes must fail closed");
        assert!(matches!(err, DeltaCasError::ChunkHashMismatch { .. }));
    }

    #[test]
    fn merkle_manifest_is_stable_and_reports_delta_ranges() {
        let old_a = DeltaChunkRef::from_bytes(0, b"aaaa");
        let old_b = DeltaChunkRef::from_bytes(4, b"bbbb");
        let old_c = DeltaChunkRef::from_bytes(8, b"cccc");
        let new_b = DeltaChunkRef::from_bytes(4, b"bXbb");

        let baseline =
            DeltaMerkleManifest::new("tree", vec![old_b, old_c, old_a]).expect("baseline");
        let same =
            DeltaMerkleManifest::new("tree", vec![old_a, old_b, old_c]).expect("same manifest");
        assert_eq!(baseline.merkle_root(), same.merkle_root());
        assert!(same.diff_against(&baseline).changed_subtrees.is_empty());

        let target = DeltaMerkleManifest::new("tree", vec![old_a, new_b, old_c]).expect("target");
        let diff = target.diff_against(&baseline);
        assert_eq!(diff.missing_chunks, vec![new_b]);
        assert_eq!(diff.stale_chunks, vec![old_b]);
        assert_eq!(
            diff.changed_subtrees,
            vec![DeltaSubtreeRange {
                start_leaf: 1,
                end_leaf: 2
            }]
        );
    }

    #[test]
    fn manifest_persistence_is_deterministic_and_deduped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let manifest = DeltaMerkleManifest::new(
            "tree",
            vec![
                DeltaChunkRef::from_bytes(0, b"left"),
                DeltaChunkRef::from_bytes(4, b"right"),
            ],
        )
        .expect("manifest");

        assert!(
            store
                .persist_manifest_new(&manifest)
                .expect("first manifest")
        );
        assert!(
            !store
                .persist_manifest_new(&manifest)
                .expect("identical manifest dedups")
        );
        assert_eq!(
            store
                .load_manifest_bytes("tree")
                .expect("load manifest")
                .expect("present"),
            manifest.to_canonical_bytes()
        );
    }
