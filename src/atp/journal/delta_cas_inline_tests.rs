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

    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    #[test]
    fn concurrent_chunk_publishers_choose_one_complete_winner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let bytes = Arc::new(vec![0x6d_u8; 256 * 1024 + 17]);
        let gate = Arc::new(Barrier::new(8));
        let writes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let store = &store;
                    let bytes = Arc::clone(&bytes);
                    let gate = Arc::clone(&gate);
                    scope.spawn(move || {
                        gate.wait();
                        store.put_chunk(&bytes).expect("concurrent publication")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("publisher joined"))
                .collect::<Vec<_>>()
        });
        assert_eq!(writes.iter().filter(|write| write.inserted).count(), 1);
        let first = writes[0];
        assert!(writes.iter().all(|write| {
            write.id == first.id && write.size_bytes == first.size_bytes
        }));
        assert_eq!(
            store.get_chunk(first.id, first.size_bytes).unwrap().unwrap(),
            *bytes
        );
    }

    #[test]
    fn partial_staging_is_invisible_and_losing_writer_preserves_winner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let bytes = b"one complete content-addressed object";
        let id = DeltaChunkId::from_bytes(bytes);
        let path = store.chunk_path(id, bytes.len() as u64);
        let (staged_tx, staged_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let staged_path = path.clone();
            let candidate = scope.spawn(move || {
                publish_file_new(&staged_path, |file| {
                    file.write_all(&bytes[..5])?;
                    staged_tx.send(()).map_err(std::io::Error::other)?;
                    resume_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(std::io::Error::other)?;
                    file.write_all(&bytes[5..])
                })
            });
            staged_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("writer reached a partial staging file");
            assert!(
                !store.has_chunk(id, bytes.len() as u64).unwrap(),
                "a partial staging file must not be addressable as a chunk"
            );
            let winner = store.put_chunk(bytes).expect("other publisher wins");
            assert!(winner.inserted);
            resume_tx.send(()).unwrap();
            assert!(
                !candidate.join().expect("writer joined").unwrap(),
                "the delayed publisher must observe an existing winner"
            );
        });
        assert_eq!(
            store.get_chunk(id, bytes.len() as u64).unwrap().unwrap(),
            bytes
        );
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1,
            "both staging names should be retired, preserving the one final object"
        );
    }

    #[test]
    fn interrupted_write_leaves_no_poisoned_final_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let bytes = b"retry after a partial disk write";
        let id = DeltaChunkId::from_bytes(bytes);
        let path = store.chunk_path(id, bytes.len() as u64);
        let error = publish_file_new(&path, |file| {
            file.write_all(&bytes[..7])?;
            Err(std::io::Error::other("injected write failure"))
        })
        .expect_err("interrupted write must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(!store.has_chunk(id, bytes.len() as u64).unwrap());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 0);
        assert!(store.put_chunk(bytes).unwrap().inserted);
        assert_eq!(
            store.get_chunk(id, bytes.len() as u64).unwrap().unwrap(),
            bytes
        );
    }

    #[test]
    fn different_manifest_is_refused_without_claiming_or_replacing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let first =
            DeltaMerkleManifest::new("same-tree", vec![DeltaChunkRef::from_bytes(0, b"first")])
                .unwrap();
        let different =
            DeltaMerkleManifest::new("same-tree", vec![DeltaChunkRef::from_bytes(0, b"second")])
                .unwrap();
        assert!(store.persist_manifest_new(&first).unwrap());
        assert!(!store.persist_manifest_new(&first).unwrap());
        assert!(matches!(
            store.persist_manifest_new(&different),
            Err(DeltaCasError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            store.load_manifest_bytes("same-tree").unwrap().unwrap(),
            first.to_canonical_bytes()
        );
    }

    #[test]
    fn concurrent_different_manifests_cannot_both_claim_publication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let candidates = [
            DeltaMerkleManifest::new("same-tree", vec![DeltaChunkRef::from_bytes(0, b"left")])
                .unwrap(),
            DeltaMerkleManifest::new("same-tree", vec![DeltaChunkRef::from_bytes(0, b"right")])
                .unwrap(),
        ];
        let gate = Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = candidates
                .iter()
                .map(|manifest| {
                    let store = &store;
                    let gate = &gate;
                    scope.spawn(move || {
                        gate.wait();
                        store.persist_manifest_new(manifest)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("manifest publisher joined"))
                .collect::<Vec<_>>()
        });
        let winners: Vec<_> = results
            .iter()
            .enumerate()
            .filter(|(_, result)| matches!(result, Ok(true)))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(winners.len(), 1);
        let winner = winners[0];
        assert!(matches!(
            &results[1 - winner],
            Err(DeltaCasError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            store.load_manifest_bytes("same-tree").unwrap().unwrap(),
            candidates[winner].to_canonical_bytes()
        );
    }

    #[test]
    fn corrupted_existing_chunk_is_reported_without_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeltaCasStore::open(dir.path()).expect("open cas");
        let bytes = vec![0x39_u8; 24_701];
        let stored = store.put_chunk(&bytes).unwrap();
        let path = store.chunk_path(stored.id, stored.size_bytes);
        for length in [bytes.len() - 1, bytes.len(), bytes.len() + 1] {
            let damaged = vec![0x72_u8; length];
            fs::write(&path, &damaged).unwrap();
            let error = store.put_chunk(&bytes).expect_err("corruption must fail closed");
            assert!(matches!(
                error,
                DeltaCasError::ChunkHashMismatch { expected, actual }
                    if expected == stored.id && actual == DeltaChunkId::from_bytes(&damaged)
            ));
            assert_eq!(fs::read(&path).unwrap(), damaged);
        }
    }
