//! Async file implementation.

#![allow(clippy::unused_async)]

use crate::fs::OpenOptions;
use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use std::fs::{Metadata, Permissions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

/// An open file on the filesystem.
#[derive(Debug)]
pub struct File {
    pub(crate) inner: std::fs::File,
}

impl File {
    /// Opens a file in read-only mode.
    ///
    /// See [`OpenOptions::open`] for more options.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = std::fs::File::open(path)?;
        Ok(Self { inner: file })
    }

    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = std::fs::File::create(path)?;
        Ok(Self { inner: file })
    }

    /// Returns a new `OpenOptions` object.
    #[must_use]
    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    pub(crate) fn from_std(file: std::fs::File) -> Self {
        Self { inner: file }
    }

    /// Attempts to sync all OS-internal metadata to disk.
    pub async fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()
    }

    /// This function is similar to `sync_all`, except that it will not sync file metadata.
    pub async fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }

    /// Truncates or extends the underlying file.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        self.inner.set_len(size)
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        self.inner.metadata()
    }

    /// Creates a new `File` instance that shares the same underlying file handle.
    pub async fn try_clone(&self) -> io::Result<Self> {
        let file = self.inner.try_clone()?;
        Ok(Self { inner: file })
    }

    /// Changes the permissions on the underlying file.
    pub async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        self.inner.set_permissions(perm)
    }

    // Helper methods that match std::fs::File but async
    
    /// Reads a number of bytes starting from a given offset.
    /// Note: using seek + read
    pub async fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }

    /// Gets the current stream position.
    pub async fn stream_position(&mut self) -> io::Result<u64> {
        self.inner.stream_position()
    }

    /// Rewinds the stream to the beginning.
    pub async fn rewind(&mut self) -> io::Result<()> {
        self.inner.rewind()
    }
}

impl AsyncRead for File {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = self.inner.read(buf.unfilled())?;
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
        let n = self.inner.write(buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.flush()?;
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
        let n = self.inner.seek(pos)?;
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{AsyncReadExt, AsyncWriteExt}; // Extension traits for read_to_string etc
    use tempfile::tempdir;

    #[test]
    fn test_file_create_write_read() {
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
            assert_eq!(contents, "hello world");
        });
    }

    #[test]
    fn test_file_seek() {
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
            assert_eq!(&buf, b"56789");
        });
    }
}
