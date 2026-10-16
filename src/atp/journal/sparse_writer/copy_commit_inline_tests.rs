    use super::*;
    use crate::atp::journal::{CommitPolicy, SparseWriterConfig, WriteOptions};
    use crate::atp::journal::sparse_writer::WriterLifecycle;
    use crate::atp::manifest::Manifest;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use std::cell::Cell;

    const OLD: &[u8] = b"existing destination must survive preparation failures";

    fn prepared(bytes: &[u8], policy: FsyncPolicy) -> (tempfile::TempDir, PathBuf, SparseWriter) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("destination");
        std::fs::write(&path, OLD).unwrap();
        let object = Object::file(bytes.to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        let manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
        let writer = SparseWriter::new_blocking(id, path.clone(), SparseWriterConfig {
            enable_preallocation: false,
            fsync_policy: policy,
            commit_policy: CommitPolicy::CopyAndVerify,
            ..SparseWriterConfig::default()
        }).unwrap();
        writer.set_expected_size(bytes.len() as u64).unwrap();
        if !bytes.is_empty() {
            writer.write_chunk_blocking(0, bytes, WriteOptions::default()).unwrap();
        }
        writer.verify_inner(&manifest, None).unwrap();
        (directory, path, writer)
    }

    fn assert_sealed_original(writer: &SparseWriter, path: &Path, original: &[u8]) -> PathBuf {
        let retained = {
            let state = writer.lock_state();
            assert_eq!(state.lifecycle, WriterLifecycle::Committing);
            assert_eq!(std::fs::read(state.temp_path.as_ref().unwrap()).unwrap(), original);
            state.publication_copy_path.clone().unwrap()
        };
        assert_eq!(std::fs::read(path).unwrap(), OLD);
        assert!(retained.exists());
        assert!(writer.path_manager.lock().get_temp_info(&retained).is_some());
        assert!(matches!(writer.commit_with_fsync(File::sync_all),
            Outcome::Err(SparseWriterError::CommitFailed(_))));
        assert!(matches!(writer.cancel_blocking(),
            Outcome::Err(SparseWriterError::CommitFailed(_))));
        retained
    }

    #[test]
    fn copy_is_verified_and_synced_before_replacing_existing_destination() {
        for size in [0, 1, 8191, 8192, 8193, 131_073] {
            for policy in [FsyncPolicy::Never, FsyncPolicy::EveryWrite,
                FsyncPolicy::VerifiedChunks, FsyncPolicy::BeforeCommit]
            {
                let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                let (_directory, path, writer) = prepared(&bytes, policy);
                let synced = Cell::new(false);
                let result = writer.commit_with_publication(File::sync_all, |writer| {
                    writer.copy_commit_with(SparseWriter::copy_exact_bytes, |copy| {
                        assert_eq!(std::fs::read(&path).unwrap(), OLD);
                        assert_eq!(copy.metadata().unwrap().len(), bytes.len() as u64);
                        let copy_path = writer.lock_state().publication_copy_path.clone().unwrap();
                        assert_eq!(std::fs::read(copy_path).unwrap(), bytes);
                        synced.set(true);
                        copy.sync_all()
                    })
                }).unwrap();
                assert_eq!(result, path);
                assert_eq!(synced.get(), policy != FsyncPolicy::Never);
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                let state = writer.lock_state();
                assert_eq!(state.lifecycle, WriterLifecycle::Committed);
                assert!(state.publication_copy_path.is_none());
                assert!(state.temp_file.is_none());
                assert!(state.temp_path.is_none());
                drop(state);
                // Repeating commit retrieves the path rather than recopying.
                assert_eq!(writer.commit_with_fsync(|_| panic!("already committed")).unwrap(), path);
            }
        }
    }

    #[test]
    fn partial_copy_failure_preserves_original_destination_and_both_staging_files() {
        let (_directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
        let result = writer.commit_with_publication(File::sync_all, |writer| {
            writer.copy_commit_with(|source, destination, _| {
                SparseWriter::copy_exact_bytes(source, destination, 3)?;
                Err(io::Error::other("injected disk failure after real partial copy"))
            }, |_| panic!("failed copy must not sync"))
        });
        assert!(matches!(result, Outcome::Err(SparseWriterError::CommitFailed(message))
            if message.contains("injected disk failure") && message.contains("retained at")));
        let copy = assert_sealed_original(&writer, &path, b"abcdefgh");
        assert_eq!(std::fs::read(copy).unwrap(), b"abc");
    }

    #[test]
    fn wrong_copy_bytes_or_lengths_never_publish_or_sync() {
        for case in 0..3 {
            let (_directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
            let result = writer.commit_with_publication(File::sync_all, |writer| {
                writer.copy_commit_with(|source, destination, length| {
                    let copied = SparseWriter::copy_exact_bytes(source, destination, length)?;
                    match case {
                        0 => { destination.seek(SeekFrom::Start(2))?; destination.write_all(b"!")?; }
                        1 => destination.set_len(length - 1)?,
                        2 => return Ok(copied - 1),
                        _ => unreachable!(),
                    }
                    Ok(copied)
                }, |_| panic!("invalid copy must not sync"))
            });
            assert!(matches!(result, Outcome::Err(SparseWriterError::CommitFailed(_))));
            assert_sealed_original(&writer, &path, b"abcdefgh");
        }
    }

    #[test]
    fn copy_sync_failure_is_before_visibility_and_keeps_its_error_category() {
        let (_directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
        let result = writer.commit_with_publication(File::sync_all, |writer| {
            writer.copy_commit_with(SparseWriter::copy_exact_bytes,
                |_| Err(io::Error::other("injected copy barrier failure")))
        });
        assert!(matches!(result, Outcome::Err(SparseWriterError::SyncFailed(message))
            if message.contains("injected copy barrier failure") && message.contains("retained at")));
        let copy = assert_sealed_original(&writer, &path, b"abcdefgh");
        assert_eq!(std::fs::read(copy).unwrap(), b"abcdefgh");
    }

    #[test]
    fn copying_or_syncing_panic_leaves_sealed_evidence_without_replacing_destination() {
        for during_copy in [false, true] {
            let (_directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                writer.commit_with_publication(File::sync_all, |writer| {
                    writer.copy_commit_with(|source, destination, length| {
                        let n = SparseWriter::copy_exact_bytes(source, destination, length)?;
                        assert!(!during_copy, "injected copy panic");
                        Ok(n)
                    }, |_| panic!("injected copy sync panic"))
                })
            }));
            assert!(result.is_err());
            assert_sealed_original(&writer, &path, b"abcdefgh");
        }
    }

    #[test]
    fn rename_failure_retains_verified_copy_and_destination_directory_contents() {
        let (directory, _, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
        let path = directory.path().join("occupied-directory");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sentinel"), OLD).unwrap();
        writer.lock_state().final_path = path.clone();
        assert!(matches!(writer.commit_with_fsync(File::sync_all),
            Outcome::Err(SparseWriterError::CommitFailed(_))));
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), OLD);
        let state = writer.lock_state();
        assert_eq!(state.lifecycle, WriterLifecycle::Committing);
        assert_eq!(std::fs::read(state.publication_copy_path.as_ref().unwrap()).unwrap(), b"abcdefgh");
        assert!(state.temp_file.is_some());
    }

    #[test]
    fn source_growth_is_refused_before_private_copy_allocation() {
        let (_directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
        writer.lock_state().temp_file.as_ref().unwrap().set_len(9).unwrap();
        assert!(matches!(writer.commit_with_fsync(File::sync_all),
            Outcome::Err(SparseWriterError::CommitFailed(_))));
        assert!(writer.lock_state().publication_copy_path.is_none());
        assert_eq!(std::fs::read(path).unwrap(), OLD);
    }

    #[cfg(unix)]
    #[test]
    fn a_replaced_staging_name_cannot_hide_corruption_in_the_owned_copy_source() {
        let (directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
        let staging = writer.lock_state().temp_path.clone().unwrap();
        std::fs::write(&staging, b"tampered").unwrap();
        std::fs::rename(&staging, directory.path().join("original-inode")).unwrap();
        // A name-only verifier would see the expected bytes while the copied
        // source descriptor still contains the corrupt original inode.
        std::fs::write(&staging, b"abcdefgh").unwrap();
        let mut graph = ObjectGraph::new();
        graph.add_root(Object::file(b"abcdefgh".to_vec())).unwrap();
        let manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
        assert!(matches!(writer.verify_inner(&manifest, None),
            Outcome::Err(SparseWriterError::VerificationFailed(_))));
        assert!(matches!(writer.commit_with_fsync(File::sync_all),
            Outcome::Err(SparseWriterError::NotVerified)));
        assert_eq!(std::fs::read(path).unwrap(), OLD);
        assert!(writer.lock_state().publication_copy_path.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn destination_symlinks_and_hardlink_aliases_are_not_followed_or_overwritten() {
        for kind in 0..3 {
            let (directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
            let alias = directory.path().join("alias");
            // Keep the old destination as an independent name without deleting
            // fixture data. The publication must replace only its target entry.
            std::fs::rename(&path, &alias).unwrap();
            match kind {
                0 => std::os::unix::fs::symlink(&alias, &path).unwrap(),
                1 => std::os::unix::fs::symlink(directory.path().join("absent"), &path).unwrap(),
                2 => std::fs::hard_link(&alias, &path).unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(writer.commit_with_fsync(File::sync_all).unwrap(), path);
            assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
            assert_eq!(std::fs::read(alias).unwrap(), OLD);
            assert!(!directory.path().join("absent").exists());
            assert!(!std::fs::symlink_metadata(path).unwrap().file_type().is_symlink());
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_copy_becomes_read_only_only_after_payload_preparation_and_still_commits() {
        use std::os::unix::fs::PermissionsExt;
        let (_directory, path, writer) = prepared(b"abcdefgh", FsyncPolicy::BeforeCommit);
        writer.lock_state().temp_file.as_ref().unwrap()
            .set_permissions(std::fs::Permissions::from_mode(0o400)).unwrap();
        let result = writer.commit_with_publication(File::sync_all, |writer| {
            writer.copy_commit_with(|source, destination, length| {
                assert_eq!(destination.metadata()?.permissions().mode() & 0o077, 0);
                SparseWriter::copy_exact_bytes(source, destination, length)
            }, |destination| {
                assert_eq!(destination.metadata()?.permissions().mode() & 0o777, 0o400);
                destination.sync_all()
            })
        });
        assert_eq!(result.unwrap(), path);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
        assert_eq!(std::fs::read(path).unwrap(), b"abcdefgh");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn scoped_finalization_replaces_only_complete_files_on_both_native_schedulers() {
        use crate::atp::journal::sparse_writer::ScopedSparseWriter;
        use crate::cx::Cx;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
        use std::sync::Arc;
        use std::time::Duration;
        for workers in [1, 2] {
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers) };
            let runtime = builder.blocking_threads(1, 2).build().unwrap();
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("destination");
            std::fs::write(&path, OLD).unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let object = Object::file(b"abcdefgh".to_vec());
                let id = object.id.clone();
                let mut graph = ObjectGraph::new();
                graph.add_root(object).unwrap();
                let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
                let writer = ScopedSparseWriter::new(&cx, id, path.clone(), SparseWriterConfig {
                    commit_policy: CommitPolicy::CopyAndVerify,
                    ..SparseWriterConfig::default()
                }).await.unwrap().unwrap();
                writer.set_expected_size(&cx, 8).await.unwrap().unwrap();
                writer.write_chunk(&cx, 4, b"efgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), OLD);
                writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), OLD);
                assert_eq!(writer.verify_and_commit(&cx, manifest).await.unwrap().unwrap(), path);
            });
            assert_eq!(std::fs::read(path).unwrap(), b"abcdefgh");
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }
    }
