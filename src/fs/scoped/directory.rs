//! Bounded directory snapshots on region-owned blocking work.

use super::{ScopedFs, ScopedFsError};
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use std::fs::FileType;
use std::io;
use std::path::{Path, PathBuf};

/// Limits on the entries retained by a scoped directory operation.
///
/// Both limits are inclusive. Paths are counted in their native encoded bytes,
/// including the supplied directory prefix, without lossy UTF-8 conversion.
/// Neither limit is allocated up front. These bound result size, not allocator
/// overhead, operating-system buffers, or the one entry being inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryReadLimits {
    /// Maximum number of entries in the result.
    pub max_entries: usize,
    /// Maximum sum of the returned paths' native encoded lengths.
    pub max_path_bytes: usize,
}

impl DirectoryReadLimits {
    /// Set both result limits explicitly; there is no implicit unbounded policy.
    #[must_use]
    pub const fn new(max_entries: usize, max_path_bytes: usize) -> Self {
        Self {
            max_entries,
            max_path_bytes,
        }
    }
}

/// An owned path and file-type observation, not an open directory entry.
///
/// Unlike `std::fs::DirEntry`, this value cannot retain a directory handle.
/// The observed type does not follow the final entry's symlink and can become
/// stale if the filesystem is modified after enumeration. This is not an open
/// file, a stable inode identity, or a path-confinement capability.
#[derive(Clone, Debug)]
pub struct ScopedDirEntry {
    path: PathBuf,
    file_type: FileType,
}

impl ScopedDirEntry {
    /// The supplied directory path joined with the entry's native name.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// File type observed during enumeration, without following this entry's symlink.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// Take the owned path without copying or decoding it.
    #[must_use]
    pub fn into_path(self) -> PathBuf {
        self.path
    }
}

impl<Caps> ScopedFs<Caps>
where
    Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
{
    /// Collect one complete directory under region ownership and explicit limits.
    ///
    /// Enumeration, file-type queries and sorting run on the owned blocking
    /// worker. The iterator and every OS directory entry are dropped before
    /// the operation retires, including on cancellation or error. Returned
    /// snapshots retain no directory handles. Names remain native `PathBuf`s;
    /// results are sorted by native path order, not by filesystem iteration
    /// order. This ordering is deterministic on a given platform, not a
    /// cross-platform byte-serialization format.
    ///
    /// The worker checkpoints before opening the directory, before each
    /// iterator advance and file-type query, and around sorting. A running OS
    /// call or sort is not preemptible. Dropping the future requests cancellation;
    /// the region remains responsible for draining the worker.
    ///
    /// A zero entry limit accepts only an empty directory. One surplus entry
    /// is inspected to distinguish an exact limit from truncation; its file
    /// type is not queried. Exceeding either limit is `Io(FileTooLarge)`, never
    /// a successful partial listing. Allocation refusal is `Io(OutOfMemory)`.
    /// Iterator and metadata errors retain their kinds; none are skipped.
    ///
    /// The supplied directory path has ordinary host path/symlink semantics.
    /// This is neither a consistent filesystem snapshot nor a sandbox.
    pub async fn read_dir_bounded(
        &self,
        path: impl Into<PathBuf>,
        limits: DirectoryReadLimits,
    ) -> Result<Vec<ScopedDirEntry>, ScopedFsError> {
        let path = path.into();
        self.run_io(move |child| {
            let mut checkpoint = || {
                child
                    .checkpoint()
                    .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))
            };
            let mut budget = DirectoryBudget::new(limits);
            read_directory(&path, &mut budget, &mut checkpoint)
        })
        .await
    }
}

// Shared by single-directory enumeration and recursive traversal. The budget
// counts all discovered entries, so a traversal cannot reset it per directory.
pub(super) struct DirectoryBudget {
    limits: DirectoryReadLimits,
    entries: usize,
    path_bytes: usize,
}

impl DirectoryBudget {
    pub(super) const fn new(limits: DirectoryReadLimits) -> Self {
        Self {
            limits,
            entries: 0,
            path_bytes: 0,
        }
    }

    fn check_next_entry(&self) -> io::Result<()> {
        if self.entries == self.limits.max_entries {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "directory operation exceeds its entry limit",
            ));
        }
        Ok(())
    }

    fn record(&mut self, path: &Path) -> io::Result<()> {
        self.check_next_entry()?;
        let length = path.as_os_str().as_encoded_bytes().len();
        if length > self.limits.max_path_bytes - self.path_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "directory operation exceeds its path-byte limit",
            ));
        }
        // The comparisons above prove these additions cannot overflow, even
        // when a caller explicitly supplies usize::MAX for either limit.
        self.entries += 1;
        self.path_bytes += length;
        Ok(())
    }
}

pub(super) fn reserve_entry<T>(entries: &mut Vec<T>, max_entries: usize) -> io::Result<()> {
    if entries.len() == entries.capacity() {
        let needed = entries.len().checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "directory result length overflow")
        })?;
        let target = entries
            .capacity()
            .saturating_mul(2)
            .max(needed)
            .min(max_entries);
        if target < needed {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "directory operation exceeds its entry limit",
            ));
        }
        entries
            .try_reserve_exact(target - entries.len())
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
    }
    Ok(())
}

pub(super) fn read_directory(
    path: &Path,
    budget: &mut DirectoryBudget,
    checkpoint: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Vec<ScopedDirEntry>> {
    checkpoint()?;
    let entries = std::fs::read_dir(path)?;
    collect_directory(entries, budget, checkpoint, |entry| {
        Ok(ScopedDirEntry {
            path: entry.path(),
            file_type: entry.file_type()?,
        })
    })
}

// The production iterator and fault-injection tests pass through the same
// loop. A checkpoint's Interrupted is never treated as a retryable OS error.
fn collect_directory<I, E>(
    mut entries: I,
    budget: &mut DirectoryBudget,
    checkpoint: &mut impl FnMut() -> io::Result<()>,
    mut snapshot: impl FnMut(E) -> io::Result<ScopedDirEntry>,
) -> io::Result<Vec<ScopedDirEntry>>
where
    I: Iterator<Item = io::Result<E>>,
{
    let mut result = Vec::new();
    loop {
        checkpoint()?;
        let Some(entry) = entries.next() else {
            break;
        };
        let entry = entry?;
        budget.check_next_entry()?;
        checkpoint()?;
        let entry = snapshot(entry)?;
        budget.record(entry.path())?;
        reserve_entry(&mut result, budget.limits.max_entries)?;
        result.push(entry);
    }
    // Close the directory iterator before CPU-only sorting and before the
    // returned snapshots can be transferred back to the caller.
    drop(entries);
    checkpoint()?;
    result.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    checkpoint()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn limits(entries: usize) -> DirectoryReadLimits {
        DirectoryReadLimits::new(entries, usize::MAX)
    }

    #[test]
    fn pre_cancelled_collection_never_advances_the_iterator() {
        let advances = Cell::new(0);
        let iterator = std::iter::from_fn(|| {
            advances.set(advances.get() + 1);
            Some(Ok(()))
        });
        let result = collect_directory(
            iterator,
            &mut DirectoryBudget::new(limits(8)),
            &mut || Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
            |()| panic!("cancelled collection must not inspect an entry"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(advances.get(), 0);
    }

    #[test]
    fn zero_limit_probes_once_without_querying_the_surplus_entry() {
        let advances = Cell::new(0);
        let iterator = std::iter::from_fn(|| {
            advances.set(advances.get() + 1);
            Some(Ok(()))
        });
        let result = collect_directory(
            iterator,
            &mut DirectoryBudget::new(limits(0)),
            &mut || Ok(()),
            |()| panic!("surplus entry must not query its file type"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(advances.get(), 1);
        assert!(collect_directory(
            std::iter::empty::<io::Result<()>>(),
            &mut DirectoryBudget::new(DirectoryReadLimits::new(0, 0)),
            &mut || Ok(()),
            |()| panic!("empty directory has no entries"),
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn iterator_and_file_type_errors_are_not_silently_skipped() {
        let result = collect_directory(
            [Err::<(), _>(io::Error::new(io::ErrorKind::PermissionDenied, "iterator"))]
                .into_iter(),
            &mut DirectoryBudget::new(limits(1)),
            &mut || Ok(()),
            |()| panic!("failed iterator must not query a file type"),
        );
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "iterator");
        let result = collect_directory(
            [Ok(())].into_iter(),
            &mut DirectoryBudget::new(limits(1)),
            &mut || Ok(()),
            |()| Err(io::Error::new(io::ErrorKind::NotFound, "entry disappeared")),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn cancellation_between_iterator_and_metadata_is_not_retried() {
        let mut checkpoints = 0;
        let result = collect_directory(
            [Ok(())].into_iter(),
            &mut DirectoryBudget::new(limits(1)),
            &mut || {
                checkpoints += 1;
                if checkpoints == 2 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            },
            |()| panic!("cancellation must prevent metadata access"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(checkpoints, 2);
    }

    #[test]
    fn native_path_budget_is_inclusive_and_overflow_safe() {
        let path = Path::new("abc");
        let length = path.as_os_str().as_encoded_bytes().len();
        let mut budget = DirectoryBudget::new(DirectoryReadLimits::new(2, length));
        budget.record(path).unwrap();
        assert_eq!(
            budget.record(Path::new("x")).unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
        assert_eq!(budget.entries, 1);
        assert_eq!(budget.path_bytes, length);
        let mut unlimited = DirectoryBudget::new(limits(usize::MAX));
        unlimited.record(path).unwrap();
        assert_eq!(unlimited.entries, 1);
    }

    #[test]
    fn public_listing_refuses_missing_runtime_and_attenuated_authority() {
        use crate::cx::Cx;
        use crate::runtime::SpawnError;

        let cx = Cx::for_testing();
        let result = futures_lite::future::block_on(
            cx.scoped_fs().read_dir_bounded("not-opened", limits(1)),
        );
        assert!(matches!(
            result,
            Err(ScopedFsError::Admission(SpawnError::RuntimeUnavailable))
        ));
        let restricted = {
            let _guard = Cx::for_testing()
                .restrict::<crate::cx::NoCaps>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let result = futures_lite::future::block_on(
            restricted.scoped_fs().read_dir_bounded("not-opened", limits(1)),
        );
        assert!(matches!(result, Err(ScopedFsError::CapabilityDenied)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use super::*;
        use crate::cx::Cx;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
        use std::sync::mpsc;
        use std::time::Duration;

        fn bounded(test: impl FnOnce() + Send + 'static) {
            let (send, receive) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
                let _ = send.send(result);
            });
            let result = receive
                .recv_timeout(Duration::from_secs(45))
                .expect("scoped directory scenario must terminate");
            worker.join().unwrap();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }

        #[test]
        fn public_listing_is_complete_sorted_bounded_and_drained() {
            bounded(|| {
                for workers in [1, 2] {
                    let root = tempfile::tempdir().unwrap();
                    let expected = ["a", "b", "c"].map(|name| root.path().join(name));
                    std::fs::write(&expected[2], b"file").unwrap();
                    std::fs::create_dir(&expected[1]).unwrap();
                    std::fs::write(&expected[0], b"file").unwrap();
                    let bytes = expected
                        .iter()
                        .map(|path| path.as_os_str().as_encoded_bytes().len())
                        .sum();
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::new().worker_threads(workers)
                    };
                    let runtime = builder.blocking_threads(1, 1).build().unwrap();
                    runtime.block_on(async {
                        let fs = Cx::current().unwrap().scoped_fs();
                        let entries = fs
                            .read_dir_bounded(
                                root.path().to_owned(),
                                DirectoryReadLimits::new(3, bytes),
                            )
                            .await
                            .unwrap();
                        assert_eq!(
                            entries.iter().map(ScopedDirEntry::path).collect::<Vec<_>>(),
                            expected.iter().map(PathBuf::as_path).collect::<Vec<_>>()
                        );
                        assert!(entries[0].file_type().is_file());
                        assert!(entries[1].file_type().is_dir());
                        for cap in [
                            DirectoryReadLimits::new(2, bytes),
                            DirectoryReadLimits::new(3, bytes - 1),
                        ] {
                            assert!(matches!(
                                fs.read_dir_bounded(root.path().to_owned(), cap).await,
                                Err(ScopedFsError::Io(error))
                                    if error.kind() == io::ErrorKind::FileTooLarge
                            ));
                        }
                        assert!(matches!(
                            fs.read_dir_bounded(root.path().join("absent"), limits(1)).await,
                            Err(ScopedFsError::Io(error))
                                if error.kind() == io::ErrorKind::NotFound
                        ));
                        assert_eq!(
                            fs.read_dir_bounded(root.path().to_owned(), limits(usize::MAX))
                                .await
                                .unwrap()
                                .len(),
                            3
                        );
                    });
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            });
        }

        #[cfg(unix)]
        #[test]
        fn native_names_survive_and_symlink_types_are_not_followed() {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;
            let root = tempfile::tempdir().unwrap();
            let raw_path = root.path().join(OsString::from_vec(vec![b'n', 0xff]));
            std::fs::write(&raw_path, b"native name").unwrap();
            let link = root.path().join("link");
            std::os::unix::fs::symlink("missing-target", &link).unwrap();
            let entries = read_directory(
                root.path(),
                &mut DirectoryBudget::new(limits(2)),
                &mut || Ok(()),
            )
            .unwrap();
            assert!(entries.iter().any(|entry| {
                entry.path() == raw_path.as_path() && entry.file_type().is_file()
            }));
            assert!(entries.iter().any(|entry| {
                entry.path() == link.as_path() && entry.file_type().is_symlink()
            }));
        }

        #[test]
        fn cancellation_after_partial_collection_returns_no_snapshot() {
            let root = tempfile::tempdir().unwrap();
            for name in ["a", "b", "c"] {
                std::fs::write(root.path().join(name), b"file").unwrap();
            }
            let mut budget = DirectoryBudget::new(limits(3));
            let mut checkpoints = 0;
            let result = read_directory(root.path(), &mut budget, &mut || {
                checkpoints += 1;
                if checkpoints == 4 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert_eq!(budget.entries, 1);
        }
    }
}
