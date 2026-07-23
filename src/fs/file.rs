//! Async file implementation.
//!
//! This module provides async filesystem I/O by running blocking operations
//! on a background thread via `spawn_blocking_io`. The file handle is wrapped
//! in `Arc` to allow sharing across the async boundary. Cursor-using operations
//! also share a gate that remains held until a started blocking syscall
//! completes, even if the awaiting future is dropped.
//!
//! The owned async methods offload filesystem calls through the runtime
//! blocking-I/O path. The poll-based traits perform immediate file syscalls
//! because regular files do not expose portable readiness notifications; use
//! the owned async methods when a call must not run on the polling thread.

#![allow(clippy::unused_async)]

use crate::fs::OpenOptions;
use crate::fs::metadata::{Metadata, Permissions};
use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use crate::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "test-internals")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "test-internals")]
use std::sync::{Condvar, Mutex as StdMutex};
use std::task::{Context, Poll};
#[cfg(feature = "test-internals")]
use std::time::Duration;

/// Deterministic handshake for testing started cursor operations.
///
/// This is a test-only API. The first cursor operation installed with this
/// probe pauses after acquiring the cursor gate and before invoking its file
/// syscall. Tests can then drop the operation's future and start a replacement
/// operation while proving that the replacement has reached, but not passed,
/// the same gate.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
#[derive(Debug)]
pub struct FileCursorOperationProbe {
    block_first: AtomicBool,
    arrivals: StdMutex<usize>,
    arrivals_cv: Condvar,
    acquisitions: StdMutex<usize>,
    first_blocked: StdMutex<bool>,
    first_blocked_cv: Condvar,
    release_first: StdMutex<bool>,
    release_first_cv: Condvar,
}

#[cfg(feature = "test-internals")]
impl FileCursorOperationProbe {
    /// Creates a probe armed to pause the first cursor operation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_first: AtomicBool::new(true),
            arrivals: StdMutex::new(0),
            arrivals_cv: Condvar::new(),
            acquisitions: StdMutex::new(0),
            first_blocked: StdMutex::new(false),
            first_blocked_cv: Condvar::new(),
            release_first: StdMutex::new(false),
            release_first_cv: Condvar::new(),
        }
    }

    fn before_gate(&self) {
        let mut arrivals = self
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *arrivals += 1;
        self.arrivals_cv.notify_all();
    }

    fn after_gate(&self) {
        {
            let mut acquisitions = self
                .acquisitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *acquisitions += 1;
        }

        if !self.block_first.swap(false, Ordering::AcqRel) {
            return;
        }

        {
            let mut first_blocked = self
                .first_blocked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *first_blocked = true;
            self.first_blocked_cv.notify_all();
        }

        let release = self
            .release_first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(
            self.release_first_cv
                .wait_while(release, |released| !*released)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    /// Waits until the first cursor operation owns the cursor gate.
    #[must_use]
    pub fn wait_until_first_blocked(&self, timeout: Duration) -> bool {
        let first_blocked = self
            .first_blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (first_blocked, _) = self
            .first_blocked_cv
            .wait_timeout_while(first_blocked, timeout, |blocked| !*blocked)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *first_blocked
    }

    /// Waits until at least `expected` cursor operations have reached the gate.
    #[must_use]
    pub fn wait_for_arrivals(&self, expected: usize, timeout: Duration) -> bool {
        let arrivals = self
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (arrivals, _) = self
            .arrivals_cv
            .wait_timeout_while(arrivals, timeout, |arrivals| *arrivals < expected)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *arrivals >= expected
    }

    /// Returns the number of operations that have acquired the cursor gate.
    #[must_use]
    pub fn acquisition_count(&self) -> usize {
        *self
            .acquisitions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Releases the first cursor operation.
    pub fn release_first(&self) {
        let mut release = self
            .release_first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *release = true;
        self.release_first_cv.notify_all();
    }
}

#[cfg(feature = "test-internals")]
impl Default for FileCursorOperationProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// An open file on the filesystem.
///
/// The file handle is wrapped in `Arc` to allow sharing across
/// `spawn_blocking_io` boundaries for async operations.
#[derive(Debug)]
pub struct File {
    pub(crate) inner: Arc<std::fs::File>,
    cursor_gate: Arc<Mutex<()>>,
    #[cfg(feature = "test-internals")]
    cursor_probe: Option<Arc<FileCursorOperationProbe>>,
}

impl File {
    async fn with_inner<R, F>(&self, op: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(Arc<std::fs::File>) -> io::Result<R> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || op(inner)).await
    }

    async fn with_cursor_inner<R, F>(&self, op: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(Arc<std::fs::File>) -> io::Result<R> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let cursor_gate = Arc::clone(&self.cursor_gate);
        #[cfg(feature = "test-internals")]
        let cursor_probe = self.cursor_probe.clone();

        spawn_blocking_io(move || {
            #[cfg(feature = "test-internals")]
            if let Some(probe) = &cursor_probe {
                probe.before_gate();
            }

            let _cursor_guard = cursor_gate.lock();

            #[cfg(feature = "test-internals")]
            if let Some(probe) = &cursor_probe {
                probe.after_gate();
            }

            op(inner)
        })
        .await
    }

    /// Opens a file in read-only mode.
    ///
    /// See [`OpenOptions::open`] for more options.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::open(&path)).await?;
        Ok(Self::from_std(file))
    }

    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::create(&path)).await?;
        Ok(Self::from_std(file))
    }

    /// Opens a file in read-write mode, failing if it already exists.
    ///
    /// The create-new operation is atomic with respect to other filesystem
    /// creators. If this succeeds, the returned file is guaranteed to be new.
    pub async fn create_new(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
        })
        .await?;
        Ok(Self::from_std(file))
    }

    /// Returns a new `OpenOptions` object.
    #[must_use]
    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    /// Creates an async `File` from a standard library file handle.
    ///
    /// This establishes a new cursor-synchronization domain. If independently
    /// duplicated standard handles share an OS cursor, wrap one handle and use
    /// [`File::try_clone`] so all async wrappers share the same cursor gate.
    #[must_use]
    pub fn from_std(file: std::fs::File) -> Self {
        Self {
            inner: Arc::new(file),
            cursor_gate: Arc::new(Mutex::new(())),
            #[cfg(feature = "test-internals")]
            cursor_probe: None,
        }
    }

    /// Consumes this wrapper and returns a standard library file handle.
    ///
    /// If the underlying handle is shared, this returns a cloned handle. This
    /// waits for any started cursor operation in this wrapper family before the
    /// standard handle escapes; later standard-handle access is outside the
    /// async wrapper's cursor gate.
    pub fn into_std(self) -> io::Result<std::fs::File> {
        let Self {
            inner,
            cursor_gate,
            #[cfg(feature = "test-internals")]
                cursor_probe: _,
        } = self;
        let _cursor_guard = cursor_gate.lock();
        match Arc::try_unwrap(inner) {
            Ok(file) => Ok(file),
            Err(shared) => shared.try_clone(),
        }
    }

    /// Attempts to sync all OS-internal metadata to disk.
    pub async fn sync_all(&self) -> io::Result<()> {
        self.with_inner(|inner| inner.sync_all()).await
    }

    /// This function is similar to `sync_all`, except that it will not sync file metadata.
    pub async fn sync_data(&self) -> io::Result<()> {
        self.with_inner(|inner| inner.sync_data()).await
    }

    /// Truncates or extends the underlying file.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        self.with_inner(move |inner| inner.set_len(size)).await
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        self.with_inner(|inner| inner.metadata())
            .await
            .map(Metadata::from_std)
    }

    /// Creates a new `File` instance that shares the same underlying file handle
    /// and cursor completion gate.
    pub async fn try_clone(&self) -> io::Result<Self> {
        let file = self.with_inner(|inner| inner.try_clone()).await?;
        Ok(Self {
            inner: Arc::new(file),
            cursor_gate: Arc::clone(&self.cursor_gate),
            #[cfg(feature = "test-internals")]
            cursor_probe: self.cursor_probe.clone(),
        })
    }

    /// Changes the permissions on the underlying file.
    pub async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        self.with_inner(move |inner| inner.set_permissions(perm.into_inner()))
            .await
    }

    // Helper methods that match std::fs::File but async.
    // Note: These require &mut self because they use the shared file cursor.
    // A started operation uses soft cancellation: dropping its future discards
    // its result but does not stop its syscall. The shared cursor gate keeps a
    // later operation from overtaking that completion. Cloned wrappers share
    // both the OS offset and the same gate.

    /// Moves the shared file cursor and returns the new position.
    ///
    /// If this future is dropped after the syscall starts, the seek may still
    /// complete. A later cursor operation waits for that completion.
    pub async fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            Seek::seek(&mut inner_ref, pos)
        })
        .await
    }

    /// Gets the current stream position.
    pub async fn stream_position(&mut self) -> io::Result<u64> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            Seek::stream_position(&mut inner_ref)
        })
        .await
    }

    /// Rewinds the stream to the beginning.
    ///
    /// If this future is dropped after the syscall starts, the rewind may still
    /// complete. A later cursor operation waits for that completion.
    pub async fn rewind(&mut self) -> io::Result<()> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            Seek::rewind(&mut inner_ref)
        })
        .await
    }

    /// Reads into an owned buffer on the blocking I/O pool.
    ///
    /// The returned buffer is the same allocation passed by the caller, allowing
    /// chunked readers to reuse a single allocation across async boundaries.
    /// If this future is dropped after the read starts, the read and its cursor
    /// advance may still complete and the owned buffer is discarded. A later
    /// cursor operation waits for that completion before accessing the file.
    pub async fn read_into_vec(&mut self, mut buf: Vec<u8>) -> io::Result<(Vec<u8>, usize)> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            let bytes_read = Read::read(&mut inner_ref, buf.as_mut_slice())?;
            Ok((buf, bytes_read))
        })
        .await
    }

    /// Installs a one-shot cursor-operation handshake for deterministic tests.
    #[cfg(feature = "test-internals")]
    #[doc(hidden)]
    pub fn install_cursor_operation_probe_for_test(
        &mut self,
        probe: Arc<FileCursorOperationProbe>,
    ) {
        self.cursor_probe = Some(probe);
    }
}

// Phase 0: Poll-based traits use direct blocking I/O against the underlying
// std::fs::File. Shared handles inherit the platform's shared-cursor semantics
// and use the same gate as the owned cursor operations.

impl AsyncRead for File {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Regular files are readiness-ready at the OS API level. This trait
        // path performs one immediate syscall; callers that need thread
        // offload should use read_into_vec().
        let _cursor_guard = self.cursor_gate.lock();
        let mut inner_ref: &std::fs::File = &self.inner;
        let n = Read::read(&mut inner_ref, buf.unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for File {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // See poll_read: this trait path performs one immediate file syscall.
        let _cursor_guard = self.cursor_gate.lock();
        let mut inner_ref: &std::fs::File = &self.inner;
        let n = Write::write(&mut inner_ref, buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // See poll_read: this trait path performs one immediate file syscall.
        let _cursor_guard = self.cursor_gate.lock();
        let mut inner_ref: &std::fs::File = &self.inner;
        Write::flush(&mut inner_ref)?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for File {
    fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        // See poll_read: this trait path performs one immediate file syscall.
        let _cursor_guard = self.cursor_gate.lock();
        let mut inner_ref: &std::fs::File = &self.inner;
        let n = Seek::seek(&mut inner_ref, pos)?;
        Poll::Ready(Ok(n))
    }
}

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
    use crate::io::{AsyncReadExt, AsyncWriteExt}; // Extension traits for read_to_string etc
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_file_create_write_read() {
        init_test("test_file_create_write_read");
        // Phase 0 is synchronous; we use a simple block_on for async tests.

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
    fn test_file_read_into_vec_reuses_owned_buffer() {
        init_test("test_file_read_into_vec_reuses_owned_buffer");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_read_into_vec.txt");
            std::fs::write(&path, b"abcdefg").unwrap();

            let mut file = File::open(&path).await.unwrap();
            let buffer = vec![0_u8; 4];
            let capacity = buffer.capacity();

            let (buffer, bytes_read) = file.read_into_vec(buffer).await.unwrap();
            crate::assert_with_log!(bytes_read == 4, "first bytes read", 4usize, bytes_read);
            crate::assert_with_log!(
                &buffer[..bytes_read] == b"abcd",
                "first chunk",
                b"abcd",
                &buffer[..bytes_read]
            );
            crate::assert_with_log!(
                buffer.capacity() == capacity,
                "buffer capacity reused",
                capacity,
                buffer.capacity()
            );

            let (buffer, bytes_read) = file.read_into_vec(buffer).await.unwrap();
            crate::assert_with_log!(bytes_read == 3, "second bytes read", 3usize, bytes_read);
            crate::assert_with_log!(
                &buffer[..bytes_read] == b"efg",
                "second chunk",
                b"efg",
                &buffer[..bytes_read]
            );
        });
        crate::test_complete!("test_file_read_into_vec_reuses_owned_buffer");
    }

    #[test]
    fn test_file_create_new_is_exclusive_and_read_write() {
        init_test("test_file_create_new_is_exclusive_and_read_write");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("exclusive.txt");

            let mut file = File::create_new(&path).await.unwrap();
            file.write_all(b"exclusive").await.unwrap();
            file.rewind().await.unwrap();

            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "exclusive",
                "create_new file is read-write",
                "exclusive",
                contents
            );
            drop(file);

            let err = File::create_new(&path)
                .await
                .expect_err("second create_new must fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::AlreadyExists,
                "create_new existing error kind",
                io::ErrorKind::AlreadyExists,
                err.kind()
            );
        });
        crate::test_complete!("test_file_create_new_is_exclusive_and_read_write");
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
    fn test_file_metadata_permissions_roundtrip_uses_fs_wrapper() {
        init_test("test_file_metadata_permissions_roundtrip_uses_fs_wrapper");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_metadata_permissions.txt");

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .await
                .unwrap();

            let mut permissions = file.metadata().await.unwrap().permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions).await.unwrap();
            let readonly = file.metadata().await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                readonly,
                "file permissions set readonly through fs wrapper",
                true,
                readonly
            );

            let mut permissions = file.metadata().await.unwrap().permissions();
            permissions.set_readonly(false);
            file.set_permissions(permissions).await.unwrap();
            let readonly = file.metadata().await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly,
                "file permissions reset through fs wrapper",
                false,
                readonly
            );
        });
        crate::test_complete!("test_file_metadata_permissions_roundtrip_uses_fs_wrapper");
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

    #[test]
    fn test_file_from_std_into_std_roundtrip() {
        init_test("test_file_from_std_into_std_roundtrip");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("std_roundtrip.txt");

            let std_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .read(true)
                .open(&path)
                .unwrap();

            let file = File::from_std(std_file);
            let mut roundtrip = file.into_std().unwrap();
            roundtrip.write_all(b"std bridge").unwrap();
            roundtrip.sync_all().unwrap();
            drop(roundtrip);

            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "std bridge",
                "roundtrip contents",
                "std bridge",
                contents
            );
        });
        crate::test_complete!("test_file_from_std_into_std_roundtrip");
    }

    #[test]
    fn test_file_into_std_when_shared() {
        init_test("test_file_into_std_when_shared");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("shared_into_std.txt");

            let file = File::create(&path).await.unwrap();
            let _other = file.try_clone().await.unwrap();
            let std_file = file.into_std().unwrap();
            let len = std_file.metadata().unwrap().len();
            crate::assert_with_log!(len == 0, "shared into_std len", 0u64, len);
        });
        crate::test_complete!("test_file_into_std_when_shared");
    }

    #[test]
    fn test_shared_arc_file_handles_support_seek_and_async_read() {
        init_test("test_shared_arc_file_handles_support_seek_and_async_read");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("shared_arc_seek_read.txt");
            std::fs::write(&path, b"0123456789").unwrap();

            let std_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let shared = Arc::new(std_file);

            let mut seeker = File {
                inner: Arc::clone(&shared),
                cursor_gate: Arc::new(Mutex::new(())),
                #[cfg(feature = "test-internals")]
                cursor_probe: None,
            };
            let mut reader = File {
                inner: Arc::clone(&shared),
                cursor_gate: Arc::clone(&seeker.cursor_gate),
                #[cfg(feature = "test-internals")]
                cursor_probe: None,
            };

            seeker.seek(SeekFrom::Start(5)).await.unwrap();
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf).await.unwrap();
            crate::assert_with_log!(
                &buf == b"56789",
                "shared handle seek/read contents",
                b"56789",
                buf
            );
        });
        crate::test_complete!("test_shared_arc_file_handles_support_seek_and_async_read");
    }
}
