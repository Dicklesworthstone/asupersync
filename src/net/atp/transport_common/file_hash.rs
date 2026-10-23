//! Bounded blocking-pool batches for the shared ATP file hashing path.
//!
//! Each job owns its file, scratch allocation and digest state. Opening, reading
//! a short file and observing EOF share one job. Larger files return to the
//! async caller after at most 128 KiB or 64 read attempts; neither file content
//! nor pending jobs accumulate. Both digest updates run on the pool worker.
//!
//! Source jobs observe the initiating context's cancellation and the current
//! caller's I/O authority while pending and between batches. Dropping the
//! hashing future prevents subsequent batches. A submitted filesystem job may
//! still finish and discard its result: this is not syscall preemption or
//! region-drained retirement. The limits bound bytes/read attempts, not time.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::atp::object::{ContentId, ContentIdHasher, ObjectId};

use super::source_io;
use super::streaming::StreamingError;

const MAX_BATCH_BYTES: usize = 128 * 1024;
const MAX_READ_ATTEMPTS: usize = 64;

struct HashState {
    file: Option<File>,
    buffer: Vec<u8>,
    sha: Sha256,
    cid: ContentIdHasher,
    size: u64,
}

impl HashState {
    fn open(path: PathBuf, chunk_size: usize) -> io::Result<Self> {
        Ok(Self {
            file: Some(File::open(path)?),
            buffer: vec![0; chunk_size.min(MAX_BATCH_BYTES)],
            sha: Sha256::new(),
            cid: ContentId::streaming(),
            size: 0,
        })
    }

    fn read_batch(mut self) -> io::Result<Self> {
        if let Some(file) = self.file.as_mut() {
            let (filled, eof) = read_bounded_chunk(file, &mut self.buffer)?;
            let chunk = &self.buffer[..filled];
            self.sha.update(chunk);
            self.cid.update(chunk);
            self.size = self.size.saturating_add(filled as u64);
            if eof {
                // Close the source on the pool worker, not the async worker.
                self.file = None;
            }
        }
        Ok(self)
    }

    fn finish(self) -> (u64, ObjectId, [u8; 32]) {
        (
            self.size,
            ObjectId::content(self.cid.finalize()),
            self.sha.finalize().into(),
        )
    }
}

/// Implementation of the public borrowed-scratch streaming API. The borrow
/// cannot enter a 'static pool job, so one bounded allocation moves between
/// jobs instead. Unlike `File::read`, this does not allocate/copy per read.
pub(super) async fn hash_file_batched(
    path: &Path,
    chunk_size: usize,
) -> Result<(u64, ObjectId, [u8; 32]), StreamingError> {
    let source_error = |error| StreamingError::new(format!("{}: {error}", path.display()));
    // Check on the caller's thread before offloading; a worker thread must not
    // turn a restricted caller into an ambient-authority filesystem operation.
    crate::cx::io_gate::require_ambient_io("fs::File::open").map_err(source_error)?;
    if chunk_size == 0 {
        return Err(source_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ATP hash buffer must not be empty",
        )));
    }
    let owned_path = path.to_path_buf();
    let mut state = source_io::run(path, "fs::File::open", move || {
        HashState::open(owned_path, chunk_size)?.read_batch()
    })
    .await?;
    while state.file.is_some() {
        state = source_io::run(path, "fs::File::read", move || state.read_batch()).await?;
    }
    Ok(state.finish())
}

/// A short read is not EOF. Exhausting the attempt budget (including EINTR)
/// returns the completed prefix, possibly empty, without inventing EOF.
/// The caller bounds bytes with the supplied slice; this helper bounds attempts.
pub fn read_bounded_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    if buffer.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ATP hash buffer must not be empty",
        ));
    }
    let mut filled = 0;
    for _ in 0..MAX_READ_ATTEMPTS {
        if filled == buffer.len() {
            return Ok((filled, false));
        }
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return Ok((filled, true)),
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok((filled, false))
}

#[cfg(test)]
#[path = "file_hash_inline_tests.rs"]
mod tests;
