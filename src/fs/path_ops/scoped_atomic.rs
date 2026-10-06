//! Atomic replacement whose staging, commit and cleanup are region-owned.

use super::{OperationProbeHook, StagedAtomicWrite, TempPathGuard, normalized_parent,
    unique_tmp_path, validate_safe_path};
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::fs::scoped::{ScopedFs, ScopedFsError};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const WRITE_CHUNK_BYTES: usize = 16 * 1024;

mod copy;

impl<Caps> ScopedFs<Caps>
where
    Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
{
    /// Atomically replace a file using one region-owned blocking operation.
    ///
    /// Creates an exclusive temporary beside the target, writes and syncs it,
    /// then renames it into place. Existing target permissions are preserved;
    /// a new target is owner-readable/writable on Unix (subject to umask).
    /// On Unix the parent directory is synced after rename. No existing target
    /// is truncated, even when staging fails or cancellation is observed.
    ///
    /// The worker checkpoints between writes of at most 16 KiB, on interrupted
    /// syscall retries, before sync and before commit. Once the final checkpoint
    /// permits commit, rename and directory sync are uninterruptible: a racing
    /// cancellation or dropped caller can still coincide with a replacement.
    /// Unlike the ordinary `fs::write_atomic`, the commit is offloaded too.
    /// The region retains the entire operation, including discarded results
    /// and temporary-file cleanup, until the blocking worker retires.
    ///
    /// An error from directory sync occurs AFTER replacement; it is not proof
    /// of rollback. Cleanup is best effort if the OS refuses temporary removal.
    /// This follows normal host path semantics in a trusted target directory,
    /// not path confinement or compare-and-swap. It replaces a symlink itself,
    /// does not update other hard links, and does not preserve all inode metadata.
    /// The same authority, explicit pool and live-region requirements as
    /// [`Self::run_io`] apply; no inline or detached fallback is used.
    ///
    /// # Errors
    /// Returns the authority/admission failures of `run_io`, an interrupted
    /// worker checkpoint, or the underlying staging/commit I/O error.
    pub async fn write_atomic(
        &self,
        path: impl Into<PathBuf>,
        contents: Vec<u8>,
    ) -> Result<(), ScopedFsError> {
        self.write_atomic_with(path, move |child, file| {
            write_checkpointed(file, &contents, || checkpoint(child))
        })
        .await
    }

    /// Produce an atomic replacement without buffering the whole output.
    ///
    /// The synchronous writer runs on the owned blocking worker and receives
    /// its child context and an empty temporary file. Returning `Err` or
    /// panicking discards staging without renaming the target. After `Ok(())`,
    /// the runtime checks cancellation, applies permissions, syncs, checks again,
    /// and commits. Use the child context to checkpoint inside a long writer.
    ///
    /// The callback must not retain cloned temporary handles, return before its
    /// writes finish, or wait for another job on the same saturated pool. This
    /// is an application callback, not a sandbox. Blocking syscalls/callbacks
    /// cannot be preempted; region close still waits for their actual retirement.
    /// Cancellation after the commit checkpoint may leave the new file installed.
    /// The durability and error boundaries are those of [`Self::write_atomic`].
    ///
    /// # Errors
    /// Preserves writer and filesystem errors. A callback panic is reported as
    /// `ScopedFsError::Join`; a refused checkpoint is `Io(Interrupted)`.
    pub async fn write_atomic_with<F>(
        &self,
        path: impl Into<PathBuf>,
        write: F,
    ) -> Result<(), ScopedFsError>
    where
        F: FnOnce(&Cx<Caps>, &mut File) -> io::Result<()> + Send + 'static,
    {
        let path = path.into();
        self.run_io(move |child| {
            let staged = stage_with(
                &path,
                true,
                || checkpoint(&child),
                |file| write(&child, file),
                OperationProbeHook::default(),
            )?;
            checkpoint(&child)?;
            staged.commit()
        })
        .await
    }
}

fn checkpoint<Caps>(cx: &Cx<Caps>) -> io::Result<()> {
    cx.checkpoint()
        .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))
}

// The legacy byte-slice API uses this same staging engine with no-op
// checkpoints and its existing creation mode. Only the new scoped path opts
// into private staging/new-file permissions; shipped legacy defaults stay put.
pub(super) fn stage_with(
    path: &Path,
    private_staging: bool,
    mut checkpoint: impl FnMut() -> io::Result<()>,
    write: impl FnOnce(&mut File) -> io::Result<()>,
    hook: OperationProbeHook,
) -> io::Result<StagedAtomicWrite> {
    validate_safe_path(path, true)?;
    checkpoint()?;
    let parent = normalized_parent(path);
    let file_name = path.file_name().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidInput, "atomic write target must include a file name",
    ))?;
    let existing_permissions = match std::fs::metadata(path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut options = File::options();
    options.create_new(true).write(true);
    #[cfg(unix)]
    if private_staging {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private_staging;

    let opened = loop {
        checkpoint()?;
        let temp = unique_tmp_path(parent, file_name);
        match options.open(&temp) {
            Ok(file) => break (TempPathGuard::new(temp), file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    // Declare the path guard first, then the file: on EVERY unwind/error the
    // handle closes before removal. Removing an open file can fail on Windows.
    let temp_path = opened.0;
    let mut file = opened.1;
    checkpoint()?;
    write(&mut file)?;
    checkpoint()?;
    if let Some(permissions) = existing_permissions {
        file.set_permissions(permissions)?;
    }
    checkpoint()?;
    file.sync_all()?;
    drop(file);
    checkpoint()?;
    hook.block_until_released();
    #[cfg(feature = "test-internals")]
    let completion_probe = hook.completion_probe();
    Ok(StagedAtomicWrite {
        target_path: path.to_owned(),
        temp_path,
        #[cfg(feature = "test-internals")]
        completion_probe,
    })
}

fn write_checkpointed(
    file: &mut impl Write,
    mut bytes: &[u8],
    mut checkpoint: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        checkpoint()?;
        let requested = bytes.len().min(WRITE_CHUNK_BYTES);
        match file.write(&bytes[..requested]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) if count <= requested => bytes = &bytes[count..],
            Ok(_) => return Err(io::Error::new(
                io::ErrorKind::InvalidData, "writer reported more bytes than requested",
            )),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
