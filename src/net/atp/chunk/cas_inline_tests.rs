    use super::*;

    fn chunk(path: &str, offset: u64, bytes: &[u8]) -> CasManifestChunk {
        CasManifestChunk {
            rel_path: path.to_string(),
            byte_offset: offset,
            address: ChunkAddress::from_bytes(bytes),
        }
    }

    #[test]
    fn cas_store_round_trips_and_deduplicates() {
        let mut store = ContentAddressedChunkStore::new();
        let first = store
            .insert_chunk(b"same chunk", Some("a".to_string()))
            .expect("first insert");
        let second = store
            .insert_chunk(b"same chunk", Some("b".to_string()))
            .expect("second insert");

        assert_eq!(first.address, second.address);
        assert!(!first.dedup_hit);
        assert!(second.dedup_hit);
        assert_eq!(store.get(&first.address), Some(b"same chunk".as_slice()));
        assert_eq!(
            store.stats(),
            CasStoreStats {
                unique_chunks: 1,
                unique_bytes: 10,
                dedup_hits: 1,
            }
        );
    }

    #[test]
    fn manifest_root_is_stable_across_input_order() {
        let a = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("b.txt", 0, b"bravo"),
                chunk("a.txt", 0, b"alpha"),
                chunk("a.txt", 5, b"-tail"),
            ],
        )
        .expect("manifest a");
        let b = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("a.txt", 5, b"-tail"),
                chunk("a.txt", 0, b"alpha"),
                chunk("b.txt", 0, b"bravo"),
            ],
        )
        .expect("manifest b");

        assert_eq!(a.root(), b.root());
        assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
    }

    #[test]
    fn subtree_delta_finds_changed_leaf_and_missing_chunk() {
        let old = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("a", 0, b"a"),
                chunk("b", 0, b"b"),
                chunk("c", 0, b"c"),
                chunk("d", 0, b"d"),
            ],
        )
        .expect("old manifest");
        let new = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("a", 0, b"a"),
                chunk("b", 0, b"b"),
                chunk("c", 0, b"C"),
                chunk("d", 0, b"d"),
            ],
        )
        .expect("new manifest");

        let delta = new.delta_against(&old);
        assert_eq!(
            delta.changed_ranges,
            vec![CasSubtreeDiff {
                start_index: 2,
                end_index: 3,
            }]
        );
        assert_eq!(delta.missing_chunks, vec![ChunkAddress::from_bytes(b"C")]);
        assert_eq!(delta.missing_bytes, 1);
    }

    #[test]
    fn journal_commitments_use_existing_proof_digest_records() {
        let manifest =
            CasMerkleManifest::from_chunks("tree", [chunk("a", 0, b"a")]).expect("manifest");
        let records = manifest.journal_commitment_records("transfer", 42);

        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0],
            JournalRecord::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp: 42,
                ..
            } if transfer_id == "transfer" && proof_type == PROOF_TYPE_ROOT && digest == &manifest.root()
        ));
        assert!(matches!(
            &records[1],
            JournalRecord::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp: 42,
                ..
            } if transfer_id == "transfer"
                && proof_type == PROOF_TYPE_MANIFEST
                && digest == &manifest.canonical_digest()
        ));
    }
