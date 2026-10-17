    use super::*;

    fn manifest_chunk(path: &str, offset: u64, bytes: &[u8]) -> CasManifestChunk {
        CasManifestChunk {
            rel_path: path.to_string(),
            byte_offset: offset,
            address: ChunkAddress::from_bytes(bytes),
        }
    }

    fn expected_digest(path: &str, bytes: &[u8]) -> [u8; 32] {
        tree_digest(&[ReassembledFile {
            rel_path: path.to_string(),
            bytes: bytes.to_vec(),
            sha256: sha256(bytes),
        }])
        .expect("tree digest")
    }

    #[test]
    fn reassembles_from_cas_and_decoded_chunks_byte_identical() {
        let unchanged = b"hello ";
        let changed = b"delta";
        let manifest = CasMerkleManifest::from_chunks(
            "tree",
            [
                manifest_chunk("file.txt", 0, unchanged),
                manifest_chunk("file.txt", unchanged.len() as u64, changed),
            ],
        )
        .expect("manifest");
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(unchanged, Some("prior/file.txt".to_string()))
            .expect("cas insert");
        let expected = [unchanged.as_slice(), changed.as_slice()].concat();
        let decoded = DeltaChunkPayload::from_bytes(changed.to_vec());

        let tree = reassemble_from_cas_and_decoded(
            &manifest,
            &cas,
            [decoded],
            expected_digest("file.txt", &expected),
        )
        .expect("reassembly");

        assert_eq!(tree.file("file.txt").expect("file").bytes, expected);
        assert_eq!(tree.cas_chunk_count(), 1);
        assert_eq!(tree.decoded_chunk_count(), 1);
        assert_eq!(tree.manifest_root, manifest.root());
    }

    #[test]
    fn missing_chunk_fails_closed_before_reassembly() {
        let manifest =
            CasMerkleManifest::from_chunks("tree", [manifest_chunk("file.txt", 0, b"missing")])
                .expect("manifest");
        let cas = ContentAddressedChunkStore::new();

        let result = reassemble_from_cas_and_decoded(
            &manifest,
            &cas,
            [],
            expected_digest("file.txt", b"missing"),
        );

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("missing from receiver CAS and decoded delta")
        ));
    }

    #[test]
    fn whole_tree_digest_mismatch_fails_closed() {
        let manifest =
            CasMerkleManifest::from_chunks("tree", [manifest_chunk("file.txt", 0, b"bytes")])
                .expect("manifest");
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(b"bytes", None).expect("cas insert");

        let result = reassemble_from_cas_and_decoded(&manifest, &cas, [], [9u8; 32]);

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("whole-tree SHA-256")
        ));
    }

    #[test]
    fn atomic_commit_leaves_existing_destination_untouched() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let destination = tmp.path().join("dst");
        fs::create_dir(&destination).expect("destination");
        fs::write(destination.join("old.txt"), b"old").expect("old file");

        let staging = tmp.path().join("stage");
        let manifest =
            CasMerkleManifest::from_chunks("tree", [manifest_chunk("new.txt", 0, b"new")])
                .expect("manifest");
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(b"new", None).expect("cas insert");

        let result = stage_and_commit_reassembled_tree(
            &manifest,
            &cas,
            [],
            expected_digest("new.txt", b"new"),
            &staging,
            &destination,
        );

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("destination already exists")
        ));
        assert_eq!(
            fs::read(destination.join("old.txt")).expect("old file"),
            b"old"
        );
        assert!(!staging.exists());
    }
