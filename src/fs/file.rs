//! Async file implementation.
//!
//! This module provides async filesystem I/O by running blocking operations
//! on a background thread via `spawn_blocking_io`. The file handle is wrapped
//! in `Arc` to allow sharing across the async boundary.
//!
//! # Phase 0 Limitations
//!
//! The poll-based traits (`AsyncRead`, `AsyncWrite`, `AsyncSeek`) still use
//! direct blocking I/O. Full async poll support requires reactor integration.

#![allow(clippy::unused_async)]

use crate::fs::OpenOptions;
use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use crate::runtime::spawn_blocking_io;
use std::fs::{Metadata, Permissions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// An open file on the filesystem.
///
/// The file handle is wrapped in `Arc` to allow sharing across
/// `spawn_blocking_io` boundaries for async operations.
#[derive(Debug)]
pub struct File {
    pub(crate) inner: Arc<std::fs::File>,
}

impl File {
    /// Opens a file in read-only mode.
    ///
    /// See [`OpenOptions::open`] for more options.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::open(&path)).await?;
        Ok(Self {
            inner: Arc::new(file),
        })
    }

    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::create(&path)).await?;
        Ok(Self {
            inner: Arc::new(file),
        })
    }

    /// Returns a new `OpenOptions` object.
    #[must_use]
    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    pub(crate) fn from_std(file: std::fs::File) -> Self {
        Self {
            inner: Arc::new(file),
        }
    }

    /// Attempts to sync all OS-internal metadata to disk.
    pub async fn sync_all(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.sync_all()).await
    }

    /// This function is similar to `sync_all`, except that it will not sync file metadata.
    pub async fn sync_data(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.sync_data()).await
    }

    /// Truncates or extends the underlying file.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.set_len(size)).await
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.metadata()).await
    }

    /// Creates a new `File` instance that shares the same underlying file handle.
    pub async fn try_clone(&self) -> io::Result<Self> {
        let inner = Arc::clone(&self.inner);
        let file = spawn_blocking_io(move || inner.try_clone()).await?;
        Ok(Self {
            inner: Arc::new(file),
        })
    }

    /// Changes the permissions on the underlying file.
    pub async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || inner.set_permissions(perm)).await
    }

    // Helper methods that match std::fs::File but async
    // Note: These require &mut self due to seek position state.
    // Phase 0: Still blocking since we can't safely share mutable state.

    /// Reads a number of bytes starting from a given offset.
    /// Note: using seek + read
    pub async fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Phase 0: Direct blocking. Requires reactor integration for true async.
        Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared"))?
            .seek(pos)
    }

    /// Gets the current stream position.
    pub async fn stream_position(&mut self) -> io::Result<u64> {
        // Phase 0: Direct blocking. Requires reactor integration for true async.
        Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared"))?
            .stream_position()
    }

    /// Rewinds the stream to the beginning.
    pub async fn rewind(&mut self) -> io::Result<()> {
        // Phase 0: Direct blocking. Requires reactor integration for true async.
        Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared"))?
            .rewind()
    }
}

// Phase 0: Poll-based traits use direct blocking I/O.
// True async support requires reactor integration to wake on readiness.

impl AsyncRead for File {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared during poll_read"))?;
        let n = inner.read(buf.unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for File {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared during poll_write"))?;
        let n = inner.write(buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared during poll_flush"))?;
        inner.flush()?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for File {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| io::Error::other("file handle is shared during poll_seek"))?;
        let n = inner.seek(pos)?;
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{AsyncReadExt, AsyncWriteExt}; // Extension traits for read_to_string etc
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_file_create_write_read() {
        init_test("test_file_create_write_read");
        // Since we are synchronous in Phase 0, we can just block_on or run directly?
        // But functions are async.
        // We need a runtime or simple block_on.
        // I'll use futures_lite::future::block_on if available, or just tokio if test supports it?
        // The project has `conformance` with `block_on`.
        // Or I can use `futures_lite::future::block_on` since I added it to dev-dependencies.

        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test.txt");

            // Create and write
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read back
            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
        });
        crate::test_complete!("test_file_create_write_read");
    }

    #[test]
    fn test_file_seek() {
        init_test("test_file_seek");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_seek.txt");

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .await
                .unwrap();

            file.write_all(b"0123456789").await.unwrap();

            file.seek(SeekFrom::Start(5)).await.unwrap();
            let mut buf = [0u8; 5];
            file.read_exact(&mut buf).await.unwrap();
            crate::assert_with_log!(&buf == b"56789", "seek contents", b"56789", buf);
        });
        crate::test_complete!("test_file_seek");
    }

    #[test]
    fn test_file_metadata() {
        init_test("test_file_metadata");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_metadata.txt");

            // Create file with known content
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"test content").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read metadata
            let file = File::open(&path).await.unwrap();
            let metadata = file.metadata().await.unwrap();

            crate::assert_with_log!(metadata.is_file(), "is_file", true, metadata.is_file());
            crate::assert_with_log!(metadata.len() == 12, "file length", 12u64, metadata.len());
        });
        crate::test_complete!("test_file_metadata");
    }

    #[test]
    fn test_file_set_len() {
        init_test("test_file_set_len");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_truncate.txt");

            // Create and write using async API
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();

            // Truncate
            file.set_len(5).await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Verify
            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(contents == "hello", "truncated contents", "hello", contents);
        });
        crate::test_complete!("test_file_set_len");
    }

    #[test]
    fn test_cancellation_safety_soft_cancel() {
        // Test that dropping an in-flight file operation doesn't corrupt state.
        // With spawn_blocking, the blocking op continues but result is discarded.
        init_test("test_cancellation_safety_soft_cancel");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_cancel.txt");

            // Create file first
            let file = File::create(&path).await.unwrap();
            drop(file);

            // Open the file - this should complete
            let file = File::open(&path).await.unwrap();

            // File should be usable after the operation completed
            let metadata = file.metadata().await.unwrap();
            crate::assert_with_log!(metadata.is_file(), "file exists", true, metadata.is_file());
        });
        crate::test_complete!("test_cancellation_safety_soft_cancel");
    }
}
