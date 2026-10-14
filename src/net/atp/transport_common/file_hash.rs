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
fn read_bounded_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
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
mod tests {
    use super::*;
    use super::super::streaming::hash_file_streaming;

    struct ShortReader<'a> {
        remaining: &'a [u8],
        max_read: usize,
        interruptions: usize,
        calls: usize,
    }

    impl Read for ShortReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.interruptions != 0 {
                self.interruptions -= 1;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = buffer.len().min(self.max_read).min(self.remaining.len());
            buffer[..n].copy_from_slice(&self.remaining[..n]);
            self.remaining = &self.remaining[n..];
            Ok(n)
        }
    }

    #[test]
    fn short_reads_and_interruptions_conserve_bytes_across_batches() {
        for length in 0..=65 {
            let expected: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            for capacity in 1..=17 {
                for max_read in [1, 2, 3, 8] {
                    let mut source = ShortReader {
                        remaining: &expected,
                        max_read,
                        interruptions: 3,
                        calls: 0,
                    };
                    let mut buffer = vec![0xa5; capacity];
                    let mut actual = Vec::new();
                    loop {
                        let previous_calls = source.calls;
                        let (n, eof) = read_bounded_chunk(&mut source, &mut buffer).unwrap();
                        assert!(source.calls - previous_calls <= MAX_READ_ATTEMPTS);
                        assert!(n <= capacity);
                        actual.extend_from_slice(&buffer[..n]);
                        if eof {
                            break;
                        }
                    }
                    assert_eq!(actual, expected, "len={length}, cap={capacity}, read={max_read}");
                }
            }
        }
    }

    #[test]
    fn interrupted_batch_exhaustion_is_not_eof() {
        let mut source = ShortReader {
            remaining: b"payload",
            max_read: 2,
            interruptions: MAX_READ_ATTEMPTS + 1,
            calls: 0,
        };
        let mut buffer = [0xa5; 16];
        assert_eq!(read_bounded_chunk(&mut source, &mut buffer).unwrap(), (0, false));
        assert_eq!(source.calls, MAX_READ_ATTEMPTS);
        assert_eq!(buffer, [0xa5; 16]);
        let (n, eof) = read_bounded_chunk(&mut source, &mut buffer).unwrap();
        assert!(eof);
        assert_eq!(&buffer[..n], b"payload");
    }

    #[test]
    fn short_read_attempt_limit_returns_only_the_valid_prefix() {
        let expected = vec![0x7b; MAX_READ_ATTEMPTS + 10];
        let mut source = ShortReader {
            remaining: &expected,
            max_read: 1,
            interruptions: 0,
            calls: 0,
        };
        let mut buffer = vec![0xa5; expected.len() + 1];
        assert_eq!(
            read_bounded_chunk(&mut source, &mut buffer).unwrap(),
            (MAX_READ_ATTEMPTS, false)
        );
        assert_eq!(&buffer[..MAX_READ_ATTEMPTS], &expected[..MAX_READ_ATTEMPTS]);
        assert_eq!(buffer[MAX_READ_ATTEMPTS], 0xa5);
    }

    #[test]
    fn partial_read_error_does_not_become_success() {
        struct FailingReader(bool);
        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                self.0 = true;
                buffer[0] = 42;
                Ok(1)
            }
        }
        let error = read_bounded_chunk(&mut FailingReader(false), &mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn empty_buffer_is_rejected_before_reading() {
        let mut source = ShortReader {
            remaining: b"nonempty",
            max_read: 1,
            interruptions: 0,
            calls: 0,
        };
        let error = read_bounded_chunk(&mut source, &mut []).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(source.calls, 0);
    }

    #[test]
    fn real_file_batches_reuse_storage_bound_work_and_close_at_eof() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        for length in [0, 1, 7, 8, 9, 16, 17, 33, MAX_BATCH_BYTES + 1] {
            let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            std::fs::write(&path, &bytes).unwrap();
            let capacity = if length > 33 { 2 * MAX_BATCH_BYTES } else { 8 };
            let mut state = HashState::open(path.clone(), capacity).unwrap();
            let allocation = state.buffer.as_ptr();
            assert_eq!(state.buffer.len(), capacity.min(MAX_BATCH_BYTES));
            let mut batches = 0;
            while state.file.is_some() {
                let before = state.size;
                state = state.read_batch().unwrap();
                batches += 1;
                assert!(state.size - before <= MAX_BATCH_BYTES as u64);
                assert_eq!(state.buffer.as_ptr(), allocation);
            }
            if length < 8 {
                assert_eq!(batches, 1, "a short file completes in the opening job");
            }
            let digest = state.finish();
            let expected_sha: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(digest.0, length as u64);
            assert_eq!(digest.1, ObjectId::content(ContentId::from_bytes(&bytes)));
            assert_eq!(digest.2, expected_sha);
        }
    }

    #[test]
    fn public_hash_matches_independent_digests_at_batch_boundaries() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        futures_lite::future::block_on(async {
            for (length, capacity) in [
                (0, 1), (1, 1), (37, 7), (257, 1), (257, 7),
                (MAX_BATCH_BYTES - 1, MAX_BATCH_BYTES),
                (MAX_BATCH_BYTES, MAX_BATCH_BYTES),
                (MAX_BATCH_BYTES + 1, MAX_BATCH_BYTES),
                (2 * MAX_BATCH_BYTES + 17, 2 * MAX_BATCH_BYTES),
            ] {
                let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
                std::fs::write(&path, &bytes).unwrap();
                let mut scratch = vec![0xa5; capacity];
                let digest = hash_file_streaming(&path, &mut scratch).await.unwrap();
                let expected_sha: [u8; 32] = Sha256::digest(&bytes).into();
                assert_eq!(digest.0, length as u64, "len={length}, cap={capacity}");
                assert_eq!(digest.1, ObjectId::content(ContentId::from_bytes(&bytes)));
                assert_eq!(digest.2, expected_sha);
            }
        });
    }

    #[test]
    fn public_hash_rejects_empty_scratch_instead_of_hashing_empty_prefix() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nonempty");
        std::fs::write(&path, b"must not silently become an empty digest").unwrap();
        let error = futures_lite::future::block_on(hash_file_streaming(&path, &mut []))
            .unwrap_err();
        assert!(error.message().contains("buffer must not be empty"));
        assert!(error.message().contains(&path.display().to_string()));
    }

    #[test]
    fn public_hash_preserves_path_errors_and_io_authority() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        std::fs::write(&path, b"payload").unwrap();
        let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
        let mut scratch = [0; 16];
        let error = futures_lite::future::block_on(
            cx.with_ambient(hash_file_streaming(&path, &mut scratch)),
        ).unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
        assert!(error.message().contains(&path.display().to_string()));
        let missing = root.path().join("missing");
        let error = futures_lite::future::block_on(hash_file_streaming(&missing, &mut scratch))
            .unwrap_err();
        assert!(error.message().contains(&missing.display().to_string()));
        let digest = futures_lite::future::block_on(hash_file_streaming(&path, &mut scratch))
            .unwrap();
        assert_eq!(digest.0, 7, "restriction must not leak into the next caller");
    }
}
