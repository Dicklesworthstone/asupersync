//! Byte-limited atomic copies on the same region-owned staging/commit boundary.

use super::{OperationProbeHook, ScopedFs, ScopedFsError, checkpoint, stage_with,
    validate_safe_path, write_checkpointed, WRITE_CHUNK_BYTES};
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

impl<Caps> ScopedFs<Caps>
where
    Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
{
    /// Copy at most `max_bytes` into an atomic replacement of `to`.
    ///
    /// Reads the source incrementally into a fixed 16 KiB scratch buffer and
    /// writes a same-directory temporary. The limit counts bytes actually read,
    /// not metadata. At the limit, a one-byte probe distinguishes exact EOF
    /// from oversized input. Oversized input is an error, never a truncated
    /// success, and the destination is not replaced. A zero limit accepts only
    /// an empty source. The returned count excludes the overflow probe.
    ///
    /// Source and staging handles, buffer, sync, rename and discarded results
    /// stay on one owned blocking operation. Checkpoints precede every read,
    /// write/retry, sync and commit. No async worker performs filesystem calls.
    /// Cancellation after the final commit checkpoint can still coincide with
    /// replacement; directory-sync failure is a post-commit error. The original
    /// region waits for retirement even after the borrowing caller is dropped.
    ///
    /// Existing destination permissions are retained; a new Unix destination
    /// starts at 0600 subject to umask. This copies bytes, not source permissions,
    /// ownership, sparse layout, timestamps or extended attributes. Source and
    /// destination may be the same file or hard-link aliases: the source is
    /// closed before rename, and its existing inode is never truncated.
    ///
    /// Normal source symlinks are followed; a destination symlink is replaced.
    /// The target directory must be trusted. This is neither path confinement,
    /// a point-in-time source snapshot nor a disk-space reservation. The limit
    /// bounds staged bytes, not physical filesystem allocation or I/O duration.
    /// All capability/pool admission rules of [`Self::run_io`] remain in force.
    ///
    /// # Errors
    /// Refusals retain the `ScopedFsError` admission variants. Oversized input
    /// returns `Io(FileTooLarge)`, checkpoint cancellation `Io(Interrupted)`,
    /// and filesystem errors retain their original kinds. No partial destination
    /// is published when reading, writing or staging fails.
    pub async fn copy_atomic_bounded(
        &self,
        from: impl Into<PathBuf>,
        to: impl Into<PathBuf>,
        max_bytes: u64,
    ) -> Result<u64, ScopedFsError> {
        let from = from.into();
        let to = to.into();
        self.run_io(move |child| {
            validate_safe_path(&from, true)?;
            let mut copied = 0;
            let staged = stage_with(&to, true, || checkpoint(&child), |file| {
                let mut source = File::open(from)?;
                copied = copy_checkpointed(&mut source, file, max_bytes, || checkpoint(&child))?;
                // The source closes here before staging sync and target commit.
                Ok(())
            }, OperationProbeHook::default())?;
            checkpoint(&child)?;
            staged.commit()?;
            Ok(copied)
        }).await
    }
}

fn copy_checkpointed(
    source: &mut impl Read,
    target: &mut impl Write,
    max_bytes: u64,
    mut checkpoint: impl FnMut() -> io::Result<()>,
) -> io::Result<u64> {
    let mut scratch = [0_u8; WRITE_CHUNK_BYTES];
    let mut copied = 0_u64;
    loop {
        checkpoint()?;
        let remaining = max_bytes - copied;
        let requested = usize::try_from(remaining.min(WRITE_CHUNK_BYTES as u64))
            .expect("request is bounded by scratch length").max(1);
        let count = match source.read(&mut scratch[..requested]) {
            Ok(0) => return Ok(copied),
            Ok(count) if count <= requested => count,
            Ok(_) => return Err(io::Error::new(
                io::ErrorKind::InvalidData, "reader reported more bytes than requested",
            )),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let count_u64 = u64::try_from(count).expect("read fits the fixed scratch buffer");
        if count_u64 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge, "source exceeds atomic copy byte limit",
            ));
        }
        write_checkpointed(target, &scratch[..count], &mut checkpoint)?;
        // count <= remaining proves this addition cannot overflow even at MAX.
        copied += count_u64;
    }
}

#[cfg(test)]
#[path = "copy_inline_tests.rs"]
mod tests;
