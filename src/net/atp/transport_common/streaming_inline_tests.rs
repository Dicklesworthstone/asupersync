    use super::*;

    fn digest_of(rel: &str, bytes: &[u8]) -> EntryDigest {
        EntryDigest {
            rel_path: rel.to_string(),
            size: bytes.len() as u64,
            content_id: ObjectId::content(ContentId::from_bytes(bytes)),
            content_sha256: Sha256::digest(bytes).into(),
        }
    }

    #[test]
    fn hex_encode_is_lowercase_two_chars_per_byte() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn merkle_root_is_deterministic_order_independent_and_64_hex() {
        let a = vec![digest_of("a.txt", b"alpha"), digest_of("b.txt", b"bravo")];
        let b = vec![digest_of("b.txt", b"bravo"), digest_of("a.txt", b"alpha")];
        let ra = flat_merkle_root_from_digests(&a);
        let rb = flat_merkle_root_from_digests(&b);
        assert_eq!(ra, rb, "merkle root must be independent of entry order");
        assert_eq!(ra.len(), 64, "sha-256 hex root is 64 chars");
        assert!(
            ra.bytes().all(|c| c.is_ascii_hexdigit()),
            "root must be lowercase hex"
        );
    }

    #[test]
    fn matches_canonical_owned_object_graph_root() {
        // Self-contained differential oracle: the streaming per-entry-digest root
        // must equal the canonical `MerkleRoot::from_graph` over an owned
        // `ObjectGraph` built from the same content — the independent path. This
        // is the byte-identical proof that the relocated math is unchanged, and
        // it covers content-dedup (two distinct paths, identical bytes).
        use crate::atp::manifest::MerkleRoot;
        use crate::atp::object::ObjectGraph;

        let files: [(&str, &[u8]); 3] = [
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("nested/dup", b"alpha"),
        ];

        let digests: Vec<EntryDigest> = files.iter().map(|(p, b)| digest_of(p, b)).collect();
        let streamed = flat_merkle_root_from_digests(&digests);

        let mut graph = ObjectGraph::new();
        let mut sorted: Vec<&(&str, &[u8])> = files.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let mut edges = Vec::new();
        for (rel, bytes) in sorted {
            let obj = Object::file(bytes.to_vec());
            let id = obj.id.clone();
            if !graph.contains_object(&id) {
                let _ = graph.add_object(obj);
            }
            edges.push(ObjectEdge::new(id, (*rel).to_string()));
        }
        let root = Object::directory(edges);
        let _ = graph.add_root(root);
        let owned = MerkleRoot::from_graph(&graph).to_hex();

        assert_eq!(
            streamed, owned,
            "streaming digest root must equal canonical owned-graph root"
        );
    }

    #[test]
    fn duplicate_content_collapses_but_path_is_committed() {
        // Two distinct paths, identical content: content-addressed dedup to a
        // single file node, yet the distinct paths still alter the root via the
        // directory edges (path is committed, content is shared).
        let dup = vec![digest_of("x", b"same"), digest_of("y", b"same")];
        let moved = vec![digest_of("x", b"same"), digest_of("z", b"same")];
        let root_dup = flat_merkle_root_from_digests(&dup);
        assert_eq!(root_dup.len(), 64);
        assert_ne!(
            root_dup,
            flat_merkle_root_from_digests(&moved),
            "renaming a committed path must change the root"
        );
    }

    #[test]
    fn empty_transfer_has_a_stable_root() {
        let r = flat_merkle_root_from_digests(&[]);
        assert_eq!(r.len(), 64);
        assert_eq!(r, flat_merkle_root_from_digests(&[]));
    }

    #[test]
    fn flat_merkle_root_from_slices_matches_digest_path() {
        let root_from_slices =
            flat_merkle_root_from_slices([("a", b"alpha".as_slice()), ("b", b"bravo".as_slice())]);
        let digests = vec![digest_of("a", b"alpha"), digest_of("b", b"bravo")];
        assert_eq!(root_from_slices, flat_merkle_root_from_digests(&digests));
    }

    #[test]
    fn staged_receive_finalizes_incremental_digest() {
        let mut recv = StagedEntryReceive::new(PathBuf::from("stage/0"));
        recv.mark_created();
        recv.update_with_chunk(b"hel");
        recv.update_with_chunk(b"lo");
        let (digest, path, created) = recv.finalize("greeting.txt".to_string());

        assert!(created);
        assert_eq!(path, PathBuf::from("stage/0"));
        assert_eq!(digest.rel_path, "greeting.txt");
        assert_eq!(digest.size, 5);
        let expected_sha: [u8; 32] = Sha256::digest(b"hello").into();
        assert_eq!(digest.content_sha256, expected_sha);
        assert_eq!(
            digest.content_id,
            ObjectId::content(ContentId::from_bytes(b"hello"))
        );
    }

    #[test]
    fn streaming_error_preserves_message() {
        let e = StreamingError::new("path/to/x: No such file or directory (os error 2)");
        assert_eq!(
            e.message(),
            "path/to/x: No such file or directory (os error 2)"
        );
        assert_eq!(
            e.clone().into_message(),
            "path/to/x: No such file or directory (os error 2)"
        );
        assert_eq!(
            format!("{e}"),
            "path/to/x: No such file or directory (os error 2)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn policy_aware_walk_emits_directory_symlink_as_leaf() {
        let root = tempfile::tempdir().expect("temporary source root");
        std::fs::create_dir(root.path().join("target")).expect("create target dir");
        std::fs::create_dir(root.path().join("dir")).expect("create link parent");
        std::os::unix::fs::symlink("../target", root.path().join("dir/nested-link"))
            .expect("create directory symlink");

        let (_, is_directory, entries) = futures_lite::future::block_on(
            collect_entries_with_policy(root.path(), &MetadataPolicy::default()),
        )
        .expect("walk preserved symlink");
        assert!(is_directory);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.rel_path.as_str())
                .collect::<Vec<_>>(),
            vec!["dir/nested-link", "target"]
        );

        let error = futures_lite::future::block_on(collect_entries_with_policy(
            root.path(),
            &MetadataPolicy::portable(),
        ))
        .expect_err("non-preserving policy must fail closed on source links");
        assert!(error.message().contains("metadata policy"));
    }

    #[cfg(windows)]
    #[test]
    fn collect_entries_rejects_non_unicode_windows_names() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let root = tempfile::tempdir().expect("temporary source root");
        let invalid_name = OsString::from_wide(&[0xd800, b'.' as u16, b'b' as u16]);
        std::fs::write(root.path().join(invalid_name), b"payload")
            .expect("create non-Unicode Windows path");

        let error = futures_lite::future::block_on(collect_entries(root.path()))
            .expect_err("non-Unicode source names must fail closed");
        assert!(error.message().contains("not valid Unicode"), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn collect_entries_rejects_windows_junctions() {
        let root = tempfile::tempdir().expect("temporary source root");
        let target = tempfile::tempdir().expect("temporary reparse target");
        std::fs::write(target.path().join("outside.txt"), b"outside")
            .expect("write target payload");
        let link = root.path().join("real-junction");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .status()
            .expect("run mklink /J");
        assert!(status.success(), "mklink /J fixture must succeed");

        let error = futures_lite::future::block_on(collect_entries(root.path()))
            .expect_err("junction source entries must fail closed");
        assert!(error.message().contains("reparse point"), "{error}");
    }
