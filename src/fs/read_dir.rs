//! Async directory reading.
//!
//! Directory iteration is offloaded in bounded batches. Cached entries retain
//! the original std handles; metadata and file-type queries are not cached.

use crate::cx::io_gate::spawn_blocking_io;
use crate::stream::Stream;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::metadata::{FileType, Metadata};

const READ_DIR_BATCH_SIZE: usize = 32;
type EntryBuffer = VecDeque<io::Result<std::fs::DirEntry>>;

/// Async directory entry iterator.
///
/// At most 32 entries are prefetched by one blocking job. Dropping a pending
/// `next_entry` future leaves the job and its entries owned by this iterator.
pub struct ReadDir {
    state: ReadDirState,
    buffered: EntryBuffer,
}

impl std::fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadDir").finish()
    }
}

type ReadDirFuture = dyn std::future::Future<
        Output = io::Result<(EntryBuffer, Option<std::fs::ReadDir>)>,
    > + Send;

enum ReadDirState {
    Idle(std::fs::ReadDir),
    Pending(Pin<Box<ReadDirFuture>>),
    Done,
}

/// Preserve iterator order and errors, stopping after the first error so the
/// caller can decide whether to continue. A full batch does not imply EOF.
fn read_batch<T>(
    inner: &mut impl Iterator<Item = io::Result<T>>,
    mut buffered: VecDeque<io::Result<T>>,
) -> (VecDeque<io::Result<T>>, bool) {
    debug_assert!(buffered.is_empty());
    for _ in 0..READ_DIR_BATCH_SIZE {
        match inner.next() {
            Some(entry) => {
                let failed = entry.is_err();
                buffered.push_back(entry);
                if failed {
                    return (buffered, false);
                }
            }
            None => return (buffered, true),
        }
    }
    (buffered, false)
}

fn read_dir_batch(
    mut inner: std::fs::ReadDir,
    buffered: EntryBuffer,
) -> (EntryBuffer, Option<std::fs::ReadDir>) {
    let (buffered, exhausted) = read_batch(&mut inner, buffered);
    // Retire the iterator on the pool worker when EOF was observed. The std
    // entries still own whatever handles their platform requires.
    let remaining = if exhausted { None } else { Some(inner) };
    (buffered, remaining)
}

impl ReadDir {
    /// Returns the next directory entry.
    ///
    /// # Cancel Safety
    ///
    /// Dropping this future before it returns an entry does not lose entries
    /// while the `ReadDir` is retained. A pending batch stays in `self` and is
    /// resumed by the next call. Dropping the iterator itself does not forcibly
    /// preempt a filesystem operation already executing on a pool worker.
    pub async fn next_entry(&mut self) -> io::Result<Option<DirEntry>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx))
            .await
            .transpose()
    }
}

/// Reads the contents of a directory.
///
/// Opening and reading the first bounded batch share one blocking-pool job.
/// Iteration errors are returned by `next_entry`, not mistaken for open errors.
///
/// # Errors
///
/// Returns an error if the directory cannot be opened.
///
/// # Cancel Safety
///
/// Dropping the future retires the opened iterator and any prefetched entries
/// when its already-started blocking job finishes; no further job is submitted.
pub async fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<ReadDir> {
    let path = path.as_ref().to_owned();
    let (buffered, inner) = spawn_blocking_io(move || {
        let inner = std::fs::read_dir(path)?;
        Ok(read_dir_batch(
            inner,
            VecDeque::with_capacity(READ_DIR_BATCH_SIZE),
        ))
    })
    .await?;
    Ok(ReadDir {
        state: inner.map_or(ReadDirState::Done, ReadDirState::Idle),
        buffered,
    })
}

/// A directory entry returned by [`ReadDir`].
#[derive(Debug)]
pub struct DirEntry {
    // Keep the original std entry alive so metadata/file_type can be offloaded
    // without re-resolving the path and changing std::fs::DirEntry semantics.
    inner: Arc<std::fs::DirEntry>,
}

impl DirEntry {
    /// Returns the full path to the entry.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.inner.path()
    }

    /// Returns the file name of the entry.
    #[must_use]
    pub fn file_name(&self) -> OsString {
        self.inner.file_name()
    }

    /// Returns the metadata for the entry.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.metadata())
            .await
            .map(Metadata::from_std)
    }

    /// Returns the file type for the entry.
    pub async fn file_type(&self) -> io::Result<FileType> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.file_type())
            .await
            .map(FileType::from_std)
    }
}

impl Stream for ReadDir {
    type Item = io::Result<DirEntry>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.buffered.is_empty() && matches!(&this.state, ReadDirState::Done) {
            return Poll::Ready(None);
        }
        // Prefetch must not let a newly restricted caller consume cached
        // entries without the gate. Keep state intact so denial cannot discard
        // entries or cancel an in-flight batch owned by this iterator.
        if let Err(error) = crate::cx::io_gate::require_ambient_io("fs") {
            return Poll::Ready(Some(Err(error)));
        }
        loop {
            if let Some(entry) = this.buffered.pop_front() {
                return Poll::Ready(Some(entry.map(|inner| DirEntry {
                    inner: Arc::new(inner),
                })));
            }
            match std::mem::replace(&mut this.state, ReadDirState::Done) {
                ReadDirState::Idle(inner) => {
                    let buffered = std::mem::take(&mut this.buffered);
                    this.state = ReadDirState::Pending(Box::pin(spawn_blocking_io(move || {
                        Ok(read_dir_batch(inner, buffered))
                    })));
                }
                ReadDirState::Pending(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok((buffered, inner))) => {
                        this.buffered = buffered;
                        this.state = inner.map_or(ReadDirState::Done, ReadDirState::Idle);
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Pending => {
                        this.state = ReadDirState::Pending(fut);
                        return Poll::Pending;
                    }
                },
                ReadDirState::Done => {
                    return Poll::Ready(None);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "read_dir_batch_tests.rs"]
mod batch_tests;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::StreamExt;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_read_dir() {
        init_test("test_read_dir");
        let dir = tempdir().unwrap();
        let path = dir.path();
        std::fs::write(path.join("a.txt"), b"a").unwrap();
        std::fs::write(path.join("b.txt"), b"b").unwrap();
        std::fs::create_dir_all(path.join("subdir")).unwrap();

        let result = futures_lite::future::block_on(async {
            let mut entries = read_dir(&path).await?;
            let mut names = Vec::new();
            while let Some(entry) = entries.next_entry().await? {
                names.push(entry.file_name().to_string_lossy().to_string());
            }
            names.sort();
            Ok::<_, io::Error>(names)
        })
        .unwrap();

        crate::assert_with_log!(
            result == vec!["a.txt", "b.txt", "subdir"],
            "entries",
            vec!["a.txt", "b.txt", "subdir"],
            result
        );
        crate::test_complete!("test_read_dir");
    }

    #[test]
    fn test_read_dir_as_stream() {
        init_test("test_read_dir_as_stream");
        let dir = tempdir().unwrap();
        let path = dir.path();
        std::fs::write(path.join("file1.txt"), b"1").unwrap();
        std::fs::write(path.join("file2.txt"), b"2").unwrap();

        let names = futures_lite::future::block_on(async {
            let entries = read_dir(&path).await.unwrap();
            let names: Vec<String> = entries
                .map(|r| r.unwrap().file_name().to_string_lossy().to_string())
                .collect()
                .await;
            let mut names = names;
            names.sort();
            names
        });

        crate::assert_with_log!(
            names == vec!["file1.txt", "file2.txt"],
            "entries",
            vec!["file1.txt", "file2.txt"],
            names
        );
        crate::test_complete!("test_read_dir_as_stream");
    }

    #[test]
    fn test_dir_entry_metadata() {
        init_test("test_dir_entry_metadata");
        let dir = tempdir().unwrap();
        let path = dir.path();
        let file_path = path.join("test.txt");
        std::fs::write(&file_path, b"content").unwrap();

        let (is_file, len) = futures_lite::future::block_on(async {
            let mut entries = read_dir(&path).await?;
            let entry = entries.next_entry().await?.expect("missing entry");
            let metadata = entry.metadata().await?;
            Ok::<_, io::Error>((metadata.is_file(), metadata.len()))
        })
        .unwrap();

        crate::assert_with_log!(is_file, "is_file", true, is_file);
        crate::assert_with_log!(len == 7, "len", 7, len);
        crate::test_complete!("test_dir_entry_metadata");
    }

    #[cfg(unix)]
    #[test]
    fn test_dir_entry_symlink_semantics() {
        init_test("test_dir_entry_symlink_semantics");
        let dir = tempdir().unwrap();
        let path = dir.path();
        let target = path.join("target.txt");
        let link = path.join("link.txt");
        std::fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let (is_symlink, metadata_is_file, metadata_is_symlink, len) =
            futures_lite::future::block_on(async {
                let mut entries = read_dir(&path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    if entry.file_name().to_string_lossy() == "link.txt" {
                        let file_type = entry.file_type().await?;
                        let metadata = entry.metadata().await?;
                        return Ok::<_, io::Error>((
                            file_type.is_symlink(),
                            metadata.is_file(),
                            metadata.file_type().is_symlink(),
                            metadata.len(),
                        ));
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "missing symlink entry",
                ))
            })
            .unwrap();

        crate::assert_with_log!(is_symlink, "file_type reports symlink", true, is_symlink);
        crate::assert_with_log!(
            !metadata_is_file,
            "metadata is not target file metadata",
            false,
            metadata_is_file
        );
        crate::assert_with_log!(
            metadata_is_symlink,
            "metadata preserves symlink semantics",
            true,
            metadata_is_symlink
        );
        crate::assert_with_log!(len > 0, "symlink metadata len", true, len > 0);
        crate::test_complete!("test_dir_entry_symlink_semantics");
    }
}
