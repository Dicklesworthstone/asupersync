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
/// Build it with [`DirectoryReadLimits::new`]: it is `#[non_exhaustive]`, so a
/// later limit can be added without breaking callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
#[path = "directory_inline_tests.rs"]
mod tests;
