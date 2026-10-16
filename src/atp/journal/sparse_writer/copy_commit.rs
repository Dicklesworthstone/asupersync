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
#[path = "copy_commit_inline_tests.rs"]
mod tests;
