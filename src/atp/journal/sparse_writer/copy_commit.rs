//! Copy-based publication prepares an independent, verified inode before rename.
//!
//! The caller holds the writer's operation lock and has sealed its lifecycle.
//! No path naming the published destination is opened for writing. Failures
//! retain the original staging inode and the private copy for investigation;
//! this helper never retries an uncertain publication or deletes evidence.

use super::{File, Path, PathBuf, Read, Seek, SeekFrom, SparseWriter, SparseWriterError, Write};
use crate::atp::journal::{CommitPolicy, FsyncPolicy};
use crate::atp::journal::temp_management::TempFileCreationError;
use crate::types::Outcome;
use std::io;

impl SparseWriter {
    pub(super) fn uses_copy_publication(&self) -> bool {
        self.config.commit_policy == CommitPolicy::CopyAndVerify
            || (cfg!(not(unix)) && self.config.commit_policy == CommitPolicy::LinkAndUnlink)
    }

    pub(super) fn open_verification_file(&self, path: &Path) -> io::Result<File> {
        if self.uses_copy_publication() {
            // The copied bytes will come from this owned inode, not from its
            // name. Verify the same inode: reopening a substituted pathname
            // could authorize different bytes from those subsequently copied.
            self.lock_state().temp_file.as_ref()
                .ok_or_else(|| io::Error::other("missing owned staging descriptor"))?
                .try_clone()
        } else {
            // Rename/link policies retain their existing name-based semantics.
            // This change does not claim to confine their pathname races.
            File::open(path)
        }
    }

    pub(super) fn copy_commit(&self) -> Outcome<PathBuf, SparseWriterError> {
        self.copy_commit_with(Self::copy_exact_bytes, File::sync_all)
    }

    // The injectable calls operate on actual, exclusively acquired files. They
    // let tests fail a real partial copy or final barrier, without replacing
    // lifecycle sealing, verification, rename, or the outer cleanup path.
    fn copy_commit_with(
        &self,
        copy: impl FnOnce(&mut File, &mut File, u64) -> io::Result<u64>,
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> Outcome<PathBuf, SparseWriterError> {
        let result = (|| {
            let (mut source, final_path, length) = {
                let state = self.lock_state();
                if state.publication_copy_path.is_some() {
                    return Err(SparseWriterError::CommitFailed(
                        "an earlier publication copy is retained; inspect it before recovery".to_owned(),
                    ));
                }
                let file = state.temp_file.as_ref().ok_or(SparseWriterError::NoTempFile)?;
                if state.temp_path.is_none() {
                    return Err(SparseWriterError::NoTempFile);
                }
                (
                    file.try_clone().map_err(commit_io)?,
                    state.final_path.clone(),
                    state.expected_size.ok_or(SparseWriterError::IncompleteData)?,
                )
            };
            source.flush().map_err(commit_io)?;
            let source_metadata = source.metadata().map_err(commit_io)?;
            if !source_metadata.is_file() || source_metadata.len() != length {
                return Err(SparseWriterError::CommitFailed(
                    "copy source no longer has the verified file length".to_owned(),
                ));
            }
            source.seek(SeekFrom::Start(0)).map_err(commit_io)?;

            // The existing manager is rooted in the final destination's parent.
            // Use its exclusive, private creation and retain the descriptor;
            // do not reopen the generated name or copy directly over final_path.
            let (copy_path, mut destination) = self.path_manager.lock()
                .create_temp_file("verified-publication")
                .map_err(|error| match error {
                    TempFileCreationError::Path(error) => {
                        SparseWriterError::CommitFailed(error.to_string())
                    }
                    TempFileCreationError::Open(error) => commit_io(error),
                })?;
            self.lock_state().publication_copy_path = Some(copy_path.clone());

            let prepared = (|| {
                let copied = copy(&mut source, &mut destination, length).map_err(commit_io)?;
                destination.flush().map_err(commit_io)?;
                if copied != length {
                    return Err(SparseWriterError::CommitFailed(
                        "copy ended before the verified file length".to_owned(),
                    ));
                }
                Self::verify_copy_handles(&mut source, &mut destination, length)?;
                // Match fs::copy's file-permission behavior, but only after all
                // payload writes and verification. Creation itself stays private.
                destination.set_permissions(source_metadata.permissions()).map_err(commit_io)?;
                if self.config.fsync_policy != FsyncPolicy::Never {
                    // This is a different inode from the original staging file.
                    // Its final barrier must succeed BEFORE its name is published.
                    sync(&destination)
                        .map_err(|error| SparseWriterError::SyncFailed(error.to_string()))?;
                }
                Ok(())
            })();
            if let Err(error) = prepared {
                return Err(retained_copy_error(error, &copy_path));
            }

            // Close before rename for platforms that disallow moving open files.
            // The writer still retains its original descriptor on rename failure.
            drop(destination);
            drop(source);
            std::fs::rename(&copy_path, &final_path)
                .map_err(|error| retained_copy_error(commit_io(error), &copy_path))?;
            {
                let mut state = self.lock_state();
                state.publication_copy_path = None;
                // The outer commit now owns directory synchronization and the
                // original staging-name cleanup. It may still fail after visibility.
                state.temp_file = None;
            }
            self.path_manager.lock().mark_committed(&copy_path, &final_path)
                .map_err(|error| SparseWriterError::CommitFailed(error.to_string()))?;
            Ok(final_path)
        })();
        match result {
            Ok(path) => Outcome::Ok(path),
            Err(error) => Outcome::Err(error),
        }
    }

    fn copy_exact_bytes(source: &mut File, destination: &mut File, length: u64) -> io::Result<u64> {
        // Bound even a source that grows during copying. The independent length
        // and hash checks below reject truncation, extension, or mismatched data.
        io::copy(&mut source.take(length), destination)
    }

    fn verify_copy_handles(
        source: &mut File,
        destination: &mut File,
        length: u64,
    ) -> Result<(), SparseWriterError> {
        let check_lengths = |source: &File, destination: &File| {
            if source.metadata().map_err(commit_io)?.len() != length
                || destination.metadata().map_err(commit_io)?.len() != length
            {
                return Err(SparseWriterError::CommitFailed(
                    "copy verification failed: file length changed".to_owned(),
                ));
            }
            Ok(())
        };
        check_lengths(source, destination)?;
        // Reuse the canonical bounded-scratch hashing implementation. Read the
        // retained descriptors, never either file's potentially replaced name.
        let source_digest = Self::hash_file_range(source, 0, length)
            .map_err(|error| SparseWriterError::CommitFailed(error.to_string()))?;
        let destination_digest = Self::hash_file_range(destination, 0, length)
            .map_err(|error| SparseWriterError::CommitFailed(error.to_string()))?;
        check_lengths(source, destination)?;
        if source_digest != destination_digest {
            return Err(SparseWriterError::CommitFailed(
                "copy verification failed: destination digest differs from temp file".to_owned(),
            ));
        }
        Ok(())
    }
}

fn commit_io(error: io::Error) -> SparseWriterError {
    SparseWriterError::CommitFailed(error.to_string())
}

fn retained_copy_error(error: SparseWriterError, path: &Path) -> SparseWriterError {
    let message = format!("{error}; private publication copy retained at {}", path.display());
    match error {
        SparseWriterError::SyncFailed(_) => SparseWriterError::SyncFailed(message),
        _ => SparseWriterError::CommitFailed(message),
    }
}

#[cfg(test)]
mod tests {
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
}
