//! Async directory reading.
//!
//! Phase 0 uses synchronous std::fs calls under async wrappers.

use crate::stream::Stream;
use std::ffi::OsString;
use std::fs::{FileType, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Async directory entry iterator.
#[derive(Debug)]
pub struct ReadDir {
    inner: std::fs::ReadDir,
}

impl ReadDir {
    /// Returns the next directory entry.
    #[allow(clippy::unused_async)]
    pub async fn next_entry(&mut self) -> io::Result<Option<DirEntry>> {
        match self.inner.next() {
            Some(Ok(entry)) => Ok(Some(DirEntry { inner: entry })),
            Some(Err(err)) => Err(err),
            None => Ok(None),
        }
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
    std::fs::read_dir(path.as_ref()).map(|inner| ReadDir { inner })
}

/// A directory entry returned by [`ReadDir`].
#[derive(Debug)]
pub struct DirEntry {
    inner: std::fs::DirEntry,
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
    #[allow(clippy::unused_async)]
    pub async fn metadata(&self) -> io::Result<Metadata> {
        self.inner.metadata()
    }

    /// Returns the file type for the entry.
    #[allow(clippy::unused_async)]
    pub async fn file_type(&self) -> io::Result<FileType> {
        self.inner.file_type()
    }
}

impl Stream for ReadDir {
    type Item = io::Result<DirEntry>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let next = this.inner.next();
        let mapped = match next {
            Some(Ok(entry)) => Some(Ok(DirEntry { inner: entry })),
            Some(Err(err)) => Some(Err(err)),
            None => None,
        };
        Poll::Ready(mapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
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
}
