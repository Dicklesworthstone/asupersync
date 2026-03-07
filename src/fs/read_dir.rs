//! Async directory reading.
//!
//! Phase 0 uses synchronous std::fs calls under async wrappers.

use crate::runtime::spawn_blocking_io;
use crate::stream::Stream;
use std::ffi::OsString;
use std::fs::{FileType, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Async directory entry iterator.
pub struct ReadDir {
    state: ReadDirState,
}

impl std::fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadDir").finish()
    }
}

type ReadDirFuture = dyn std::future::Future<
        Output = io::Result<(Option<io::Result<std::fs::DirEntry>>, std::fs::ReadDir)>,
    > + Send;

enum ReadDirState {
    Idle(std::fs::ReadDir),
    Pending(Pin<Box<ReadDirFuture>>),
    Done,
}

impl ReadDir {
    /// Returns the next directory entry.
    pub async fn next_entry(&mut self) -> io::Result<Option<DirEntry>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx))
            .await
            .transpose()
    }
}

/// Reads the contents of a directory.
///
/// # Errors
///
/// Returns an error if the directory cannot be opened.
///
/// # Cancel Safety
///
/// This operation is cancel-safe in Phase 0.
pub async fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<ReadDir> {
    let path = path.as_ref().to_owned();
    let inner = spawn_blocking_io(move || std::fs::read_dir(path)).await?;
    Ok(ReadDir {
        state: ReadDirState::Idle(inner),
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
        spawn_blocking_io(move || inner.metadata()).await
    }

    /// Returns the file type for the entry.
    pub async fn file_type(&self) -> io::Result<FileType> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.file_type()).await
    }
}

impl Stream for ReadDir {
    type Item = io::Result<DirEntry>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match std::mem::replace(&mut self.state, ReadDirState::Done) {
                ReadDirState::Idle(mut inner) => {
                    let fut = Box::pin(spawn_blocking_io(move || {
                        let next = inner.next();
                        Ok((next, inner))
                    }));
                    self.state = ReadDirState::Pending(fut);
                }
                ReadDirState::Pending(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok((Some(Ok(entry)), inner))) => {
                        self.state = ReadDirState::Idle(inner);
                        return Poll::Ready(Some(Ok(DirEntry {
                            inner: Arc::new(entry),
                        })));
                    }
                    Poll::Ready(Ok((Some(Err(err)), inner))) => {
                        self.state = ReadDirState::Idle(inner);
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Ready(Ok((None, _inner))) => {
                        self.state = ReadDirState::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Pending => {
                        self.state = ReadDirState::Pending(fut);
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
mod tests {
    use super::*;
    use crate::stream::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("asupersync_test_{name}_{id}"));
        path
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_read_dir() {
        init_test("test_read_dir");
        let path = unique_temp_dir("read_dir");
        std::fs::create_dir_all(&path).unwrap();
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
        let _ = std::fs::remove_dir_all(&path);
        crate::test_complete!("test_read_dir");
    }

    #[test]
    fn test_read_dir_as_stream() {
        init_test("test_read_dir_as_stream");
        let path = unique_temp_dir("read_dir_stream");
        std::fs::create_dir_all(&path).unwrap();
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
        let _ = std::fs::remove_dir_all(&path);
        crate::test_complete!("test_read_dir_as_stream");
    }

    #[test]
    fn test_dir_entry_metadata() {
        init_test("test_dir_entry_metadata");
        let path = unique_temp_dir("dir_entry_metadata");
        std::fs::create_dir_all(&path).unwrap();
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
        let _ = std::fs::remove_dir_all(&path);
        crate::test_complete!("test_dir_entry_metadata");
    }

    #[cfg(unix)]
    #[test]
    fn test_dir_entry_symlink_semantics() {
        init_test("test_dir_entry_symlink_semantics");
        let path = unique_temp_dir("dir_entry_symlink_semantics");
        std::fs::create_dir_all(&path).unwrap();
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
        let _ = std::fs::remove_dir_all(&path);
        crate::test_complete!("test_dir_entry_symlink_semantics");
    }
}
