//! Size-limited, cooperatively cancellable reads on region-owned blocking work.

use super::{ScopedFs, ScopedFsError};
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use std::io::{self, Read};
use std::path::PathBuf;

const READ_CHUNK_BYTES: usize = 16 * 1024;

impl<Caps> ScopedFs<Caps>
where
    Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
{
    /// Read a complete file of at most `max_bytes` under region ownership.
    ///
    /// The limit applies to bytes actually read, not a metadata size that can
    /// become stale or be zero for a virtual file. At the limit, one additional
    /// byte is probed to distinguish exact-size EOF from oversized input. An
    /// oversized file is an error, never a successful truncated read. A zero
    /// limit accepts only an empty file. The limit is not allocated up front.
    ///
    /// The worker checkpoints before each read (at most 16 KiB) and before
    /// retrying an interrupted syscall. Cancellation stops further reads once
    /// observed; a running open/read syscall itself is not preemptible. The
    /// region owns the worker, file and abandoned buffer until retirement,
    /// including when the borrowing future is dropped.
    ///
    /// Buffer allocation requests never exceed `max_bytes`, plus a fixed read
    /// scratch buffer; allocator overhead and rounding are not an RSS bound.
    /// This follows ordinary path/symlink semantics, not path confinement or a
    /// point-in-time snapshot of a concurrently modified file.
    ///
    /// # Errors
    ///
    /// Preserves the authority/admission errors of [`Self::run_io`]. Worker
    /// checkpoint errors are `Io(Interrupted)`, excess bytes `Io(FileTooLarge)`,
    /// and failed buffer reservations `Io(OutOfMemory)`. Other I/O errors retain
    /// their original kinds. No partial buffer is returned on failure.
    pub async fn read_bounded(
        &self,
        path: impl Into<PathBuf>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ScopedFsError> {
        let path = path.into();
        self.run_io(move |child| {
            let mut file = std::fs::File::open(path)?;
            read_bounded_reader(&mut file, max_bytes, || {
                child.checkpoint().map_err(|error| {
                    io::Error::new(io::ErrorKind::Interrupted, error)
                })
            })
        })
        .await
    }

    /// Read at most `max_bytes` as UTF-8 without decoding on the async worker.
    ///
    /// The limit counts encoded bytes, not Unicode characters. The same size,
    /// cancellation and ownership rules as [`Self::read_bounded`] apply. UTF-8
    /// decoding happens inside the owned blocking operation and invalid input
    /// returns `Io(InvalidData)` without retaining the file contents in the error.
    pub async fn read_to_string_bounded(
        &self,
        path: impl Into<PathBuf>,
        max_bytes: usize,
    ) -> Result<String, ScopedFsError> {
        let path = path.into();
        self.run_io(move |child| {
            let mut file = std::fs::File::open(path)?;
            let bytes = read_bounded_reader(&mut file, max_bytes, || {
                child.checkpoint().map_err(|error| {
                    io::Error::new(io::ErrorKind::Interrupted, error)
                })
            })?;
            String::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.utf8_error()))
        })
        .await
    }
}

// The filesystem entry points above and the fault-injection tests below use
// this same reader. Checkpoint failures must not go through the syscall EINTR
// retry branch: cancellation is itself represented as Interrupted.
fn read_bounded_reader(
    reader: &mut impl Read,
    max_bytes: usize,
    mut checkpoint: impl FnMut() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::<u8>::new();
    let mut scratch = [0_u8; READ_CHUNK_BYTES];
    loop {
        checkpoint()?;
        let remaining = max_bytes - bytes.len();
        let requested = remaining.min(scratch.len()).max(1);
        let count = match reader.read(&mut scratch[..requested]) {
            Ok(0) => return Ok(bytes),
            Ok(count) if count <= requested => count,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reader reported more bytes than requested",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if count > remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!("file exceeds bounded read limit of {max_bytes} bytes"),
            ));
        }
        // count <= remaining proves both this addition and the subtraction
        // below cannot overflow, even when the caller supplies usize::MAX.
        let needed = bytes.len() + count;
        if needed > bytes.capacity() {
            let target = bytes.capacity().saturating_mul(2).max(needed).min(max_bytes);
            bytes.try_reserve_exact(target - bytes.len())
                .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        }
        bytes.extend_from_slice(&scratch[..count]);
    }
}

#[cfg(test)]
#[path = "bounded_inline_tests.rs"]
mod tests;
