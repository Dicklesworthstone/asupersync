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
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_exact_and_oversized_inputs_have_distinct_results() {
        for limit in [0, 1, READ_CHUNK_BYTES, READ_CHUNK_BYTES + 1] {
            let input = vec![42; limit];
            let mut reader = Cursor::new(input.clone());
            assert_eq!(read_bounded_reader(&mut reader, limit, || Ok(())).unwrap(), input);
            let mut oversized = Cursor::new(vec![42; limit + 1]);
            let error = read_bounded_reader(&mut oversized, limit, || Ok(())).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        }
    }

    #[test]
    fn oversized_input_consumes_only_one_extra_byte_and_returns_no_prefix() {
        let mut reader = Cursor::new(b"abcdefgh");
        let error = read_bounded_reader(&mut reader, 3, || Ok(())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn huge_limit_does_not_trigger_eager_allocation_or_overflow() {
        let mut reader = Cursor::new(b"small");
        let result = read_bounded_reader(&mut reader, usize::MAX, || Ok(())).unwrap();
        assert_eq!(result, b"small");
    }

    struct Fragmented<R> {
        inner: R,
        interruptions: usize,
        reads: usize,
    }

    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.interruptions > 0 {
                self.interruptions -= 1;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let length = output.len().min(1);
            self.inner.read(&mut output[..length])
        }
    }

    #[test]
    fn short_reads_and_interrupted_syscalls_do_not_become_early_eof() {
        let mut reader = Fragmented {
            inner: Cursor::new(b"abc"),
            interruptions: 2,
            reads: 0,
        };
        let mut checkpoints = 0;
        let bytes = read_bounded_reader(&mut reader, 3, || {
            checkpoints += 1;
            Ok(())
        }).unwrap();
        assert_eq!(bytes, b"abc");
        assert_eq!(reader.reads, 6);
        assert_eq!(checkpoints, reader.reads);
    }

    #[test]
    fn checkpoint_cancellation_is_not_retried_as_syscall_interruption() {
        let mut reader = Fragmented {
            inner: Cursor::new(b"abc"),
            interruptions: usize::MAX,
            reads: 0,
        };
        let mut checkpoints = 0;
        let error = read_bounded_reader(&mut reader, 3, || {
            checkpoints += 1;
            if checkpoints == 3 {
                Err(io::Error::new(io::ErrorKind::Interrupted, "caller cancelled"))
            } else {
                Ok(())
            }
        }).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(error.to_string(), "caller cancelled");
        assert_eq!(reader.reads, 2);
        assert_eq!(checkpoints, 3);
    }

    #[test]
    fn cancelled_checkpoint_prevents_the_first_read() {
        let mut reader = Cursor::new(b"not read");
        let error = read_bounded_reader(&mut reader, 8, || {
            Err(io::ErrorKind::Interrupted.into())
        }).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn cancellation_between_chunks_stops_before_the_next_read() {
        let mut reader = Cursor::new(vec![1; 3 * READ_CHUNK_BYTES]);
        let mut checkpoints = 0;
        let error = read_bounded_reader(&mut reader, usize::MAX, || {
            checkpoints += 1;
            if checkpoints == 2 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        }).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(reader.position(), READ_CHUNK_BYTES as u64);
    }

    struct FailedRead;

    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "read refused"))
        }
    }

    #[test]
    fn noninterrupted_io_error_keeps_its_kind_and_message() {
        let error = read_bounded_reader(&mut FailedRead, 5, || Ok(())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "read refused");
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use super::*;
        use crate::cx::{ChildRegionSpec, Cx};
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
        use crate::types::CancelKind;
        use std::io::Write;
        use std::sync::mpsc;
        use std::time::Duration;

        fn bounded(test: impl FnOnce() + Send + 'static) {
            let (send, receive) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
                let _ = send.send(result);
            });
            let result = receive.recv_timeout(Duration::from_secs(45))
                .expect("bounded filesystem scenario must terminate");
            worker.join().unwrap();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }

        fn runtime(workers: usize) -> Runtime {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::new().worker_threads(workers)
            };
            builder.blocking_threads(1, 1).build().unwrap()
        }

        fn assert_drained(runtime: &Runtime) {
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }

        #[test]
        fn file_growth_after_the_initial_read_is_not_silently_truncated() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("growing");
            std::fs::write(&path, b"small").unwrap();
            let mut reader = std::fs::File::open(&path).unwrap();
            let mut checkpoints = 0;
            let error = read_bounded_reader(&mut reader, 5, || {
                checkpoints += 1;
                if checkpoints == 2 {
                    std::fs::OpenOptions::new().append(true).open(&path)?.write_all(b"!")?;
                }
                Ok(())
            }).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
            assert_eq!(std::fs::read(path).unwrap(), b"small!");
        }

        #[test]
        fn public_bounded_reads_on_current_thread_and_multiworker_runtimes() {
            bounded(|| {
                for workers in [1, 2] {
                    let directory = tempfile::tempdir().unwrap();
                    let path = directory.path().join("bytes");
                    let runtime = runtime(workers);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        // Preserve both historical public paths as actual aliases.
                        let fs: crate::cx::scoped_fs::ScopedFs = cx.scoped_fs();
                        let fs: crate::fs::scoped::ScopedFs = fs;
                        for length in [0, 1, READ_CHUNK_BYTES, 2 * READ_CHUNK_BYTES + 7] {
                            let bytes = vec![b'x'; length];
                            fs.write(path.clone(), bytes.clone()).await.unwrap();
                            assert_eq!(fs.read_bounded(path.clone(), length).await.unwrap(), bytes);
                            assert_eq!(fs.read_bounded(path.clone(), usize::MAX).await.unwrap(), bytes);
                            if length > 0 {
                                assert!(matches!(fs.read_bounded(path.clone(), length - 1).await,
                                    Err(ScopedFsError::Io(error)) if error.kind() == io::ErrorKind::FileTooLarge));
                                assert_eq!(fs.read_bounded(path.clone(), length).await.unwrap(), bytes);
                            }
                        }
                        assert!(matches!(fs.read_bounded(path.with_file_name("absent"), 4).await,
                            Err(ScopedFsError::Io(error)) if error.kind() == io::ErrorKind::NotFound));
                    });
                    assert_drained(&runtime);
                }
            });
        }

        #[test]
        fn bounded_utf8_counts_bytes_and_preserves_invalid_data_errors() {
            bounded(|| {
                for workers in [1, 2] {
                    let directory = tempfile::tempdir().unwrap();
                    let path = directory.path().join("text");
                    let runtime = runtime(workers);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let fs = cx.scoped_fs();
                        let text = "h\u{e9}llo";
                        fs.write(path.clone(), text.as_bytes().to_vec()).await.unwrap();
                        assert_eq!(fs.read_to_string_bounded(path.clone(), text.len()).await.unwrap(), text);
                        assert!(matches!(fs.read_to_string_bounded(path.clone(), text.len() - 1).await,
                            Err(ScopedFsError::Io(error)) if error.kind() == io::ErrorKind::FileTooLarge));
                        fs.write(path.clone(), vec![0xff]).await.unwrap();
                        assert!(matches!(fs.read_to_string_bounded(path.clone(), 1).await,
                            Err(ScopedFsError::Io(error)) if error.kind() == io::ErrorKind::InvalidData));
                        fs.write(path.clone(), Vec::new()).await.unwrap();
                        assert_eq!(fs.read_to_string_bounded(path.clone(), 0).await.unwrap(), "");
                    });
                    assert_drained(&runtime);
                }
            });
        }

        #[test]
        fn bounded_entry_points_refuse_cancellation_and_attenuated_authority() {
            bounded(|| {
                for workers in [1, 2] {
                    let directory = tempfile::tempdir().unwrap();
                    let missing = directory.path().join("must-not-open");
                    let runtime = runtime(workers);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                        let child = region.cx();
                        child.cancel_with(CancelKind::User, Some("before bounded read"));
                        assert!(matches!(child.scoped_fs().read_bounded(missing.clone(), 1).await,
                            Err(ScopedFsError::Checkpoint(_))));
                        assert!(matches!(child.scoped_fs().read_to_string_bounded(missing.clone(), 1).await,
                            Err(ScopedFsError::Checkpoint(_))));
                        region.close().await.unwrap();
                        let restricted = {
                            let _guard = cx.restrict::<crate::cx::NoCaps>().set_current_restricted();
                            Cx::current().unwrap()
                        };
                        assert!(matches!(restricted.scoped_fs().read_bounded(missing.clone(), 1).await,
                            Err(ScopedFsError::CapabilityDenied)));
                        assert!(matches!(restricted.scoped_fs().read_to_string_bounded(missing.clone(), 1).await,
                            Err(ScopedFsError::CapabilityDenied)));
                    });
                    assert_drained(&runtime);
                }
            });
        }
    }
}
