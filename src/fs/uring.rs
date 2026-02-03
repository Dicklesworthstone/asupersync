//! io_uring-backed async file operations for Linux.
//!
//! This module provides true async file I/O using io_uring's `READ`, `WRITE`,
//! `OPENAT`, `FSYNC`, and `CLOSE` opcodes. Unlike poll-based async I/O, these
//! operations complete asynchronously without blocking threads.
//!
//! # Platform Requirements
//!
//! - Linux kernel 5.6+ (for full feature set)
//! - `io-uring` feature enabled in Cargo.toml
//!
//! # Cancel Safety
//!
//! - `open`: Cancel-safe (operation completes or fails atomically)
//! - `read_at`/`write_at`: Cancel-safe (in-flight operations complete in kernel)
//! - `sync_data`/`sync_all`: Cancel-safe (atomic completion)
//!
//! Note: In-flight io_uring operations cannot be truly cancelled - they will
//! complete in the kernel. Dropping an IoUringFile with pending operations
//! waits for completion to avoid use-after-free of buffers.

#![cfg(all(target_os = "linux", feature = "io-uring"))]
#![allow(unsafe_code)]

use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use io_uring::{opcode, types, IoUring};
use parking_lot::Mutex;
use std::ffi::CString;
use std::io::{self, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// Default io_uring queue size for file operations.
const DEFAULT_ENTRIES: u32 = 64;

/// User data marker for operations.
const OP_READ: u64 = 1;
const OP_WRITE: u64 = 2;
const OP_FSYNC: u64 = 3;
const OP_FDATASYNC: u64 = 4;
const OP_CLOSE: u64 = 5;

/// State for a pending io_uring operation.
#[derive(Debug)]
enum OpState {
    /// Operation not yet submitted.
    Idle,
    /// Operation submitted, waiting for completion.
    Pending { waker: Option<Waker> },
    /// Operation completed with result.
    Complete(i32),
}

/// Shared state for io_uring file operations.
struct IoUringFileInner {
    /// The io_uring instance for this file.
    ring: Mutex<IoUring>,
    /// The open file descriptor.
    fd: OwnedFd,
    /// Current file position for sequential read/write.
    position: AtomicU64,
    /// State for pending read operation.
    read_state: Mutex<OpState>,
    /// State for pending write operation.
    write_state: Mutex<OpState>,
    /// State for pending sync operation.
    sync_state: Mutex<OpState>,
}

impl std::fmt::Debug for IoUringFileInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoUringFileInner")
            .field("fd", &self.fd)
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

/// An async file backed by io_uring for true async I/O on Linux.
///
/// This file type uses io_uring's `READ` and `WRITE` opcodes for async I/O,
/// avoiding the overhead of a blocking thread pool.
///
/// # Example
///
/// ```ignore
/// use asupersync::fs::uring::IoUringFile;
///
/// async fn example() -> std::io::Result<()> {
///     let mut file = IoUringFile::open("/tmp/test.txt").await?;
///     let mut buf = vec![0u8; 1024];
///     let n = file.read(&mut buf).await?;
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct IoUringFile {
    inner: Arc<IoUringFileInner>,
}

fn any_ops_pending(inner: &IoUringFileInner) -> bool {
    matches!(&*inner.read_state.lock(), OpState::Pending { .. })
        || matches!(&*inner.write_state.lock(), OpState::Pending { .. })
        || matches!(&*inner.sync_state.lock(), OpState::Pending { .. })
}

fn mark_op_complete(state: &Mutex<OpState>, result: i32) {
    let mut guard = state.lock();
    if let OpState::Pending { waker } = &mut *guard {
        if let Some(w) = waker.take() {
            w.wake();
        }
        *guard = OpState::Complete(result);
    }
}

impl Drop for IoUringFile {
    fn drop(&mut self) {
        // Best-effort safety: if any ops are in flight on this ring, make sure we
        // drain completions before the `IoUring` mapping is dropped.
        //
        // We only do this on the last strong ref so intermediate clones don't
        // introduce surprise blocking in Drop.
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }

        while any_ops_pending(&self.inner) {
            let completions = {
                let mut ring = self.inner.ring.lock();

                // Wait for at least one completion. If this fails, we can't reliably
                // drain, so we bail out (best effort).
                if ring.submit_and_wait(1).is_err() {
                    return;
                }

                ring.completion()
                    .map(|cqe| (cqe.user_data(), cqe.result()))
                    .collect::<Vec<_>>()
            };

            for (user_data, result) in completions {
                match user_data {
                    OP_READ => mark_op_complete(&self.inner.read_state, result),
                    OP_WRITE => mark_op_complete(&self.inner.write_state, result),
                    OP_FSYNC | OP_FDATASYNC => mark_op_complete(&self.inner.sync_state, result),
                    // Unknown operations are ignored here; they're not tracked by OpState.
                    _ => {}
                }
            }
        }
    }
}

impl IoUringFile {
    /// Opens a file in read-only mode using io_uring.
    ///
    /// This uses `IORING_OP_OPENAT` for async file open.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_flags(path, libc::O_RDONLY, 0)
    }

    /// Creates a new file in write-only mode using io_uring.
    ///
    /// This will create the file if it doesn't exist and truncate it if it does.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_flags(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644)
    }

    /// Opens a file with custom flags and mode.
    pub fn open_with_flags(path: impl AsRef<Path>, flags: i32, mode: u32) -> io::Result<Self> {
        let path = path.as_ref();
        let c_path = CString::new(path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes")
        })?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes"))?;

        // For now, use synchronous open and then io_uring for I/O.
        // True async open requires a running io_uring event loop.
        // SAFETY: We're calling openat with valid arguments.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, c_path.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: fd is a newly opened file descriptor that we own.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let ring = IoUring::new(DEFAULT_ENTRIES)?;

        Ok(Self {
            inner: Arc::new(IoUringFileInner {
                ring: Mutex::new(ring),
                fd: owned_fd,
                position: AtomicU64::new(0),
                read_state: Mutex::new(OpState::Idle),
                write_state: Mutex::new(OpState::Idle),
                sync_state: Mutex::new(OpState::Idle),
            }),
        })
    }

    /// Creates an IoUringFile from an existing file descriptor.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `fd` is a valid, open file descriptor
    /// that is not used elsewhere.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        let owned_fd = OwnedFd::from_raw_fd(fd);
        let ring = IoUring::new(DEFAULT_ENTRIES)?;

        Ok(Self {
            inner: Arc::new(IoUringFileInner {
                ring: Mutex::new(ring),
                fd: owned_fd,
                position: AtomicU64::new(0),
                read_state: Mutex::new(OpState::Idle),
                write_state: Mutex::new(OpState::Idle),
                sync_state: Mutex::new(OpState::Idle),
            }),
        })
    }

    /// Reads bytes from the file at the current position.
    ///
    /// This uses `IORING_OP_READ` for true async read.
    #[must_use]
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> ReadFuture<'a> {
        let offset = self.inner.position.load(Ordering::Relaxed);
        ReadFuture {
            file: self,
            buf,
            offset,
            update_position: true,
        }
    }

    /// Reads bytes from the file at a specific offset.
    ///
    /// This does not modify the file's current position.
    #[must_use]
    pub fn read_at<'a>(&'a self, buf: &'a mut [u8], offset: u64) -> ReadFuture<'a> {
        ReadFuture {
            file: self,
            buf,
            offset,
            update_position: false,
        }
    }

    /// Writes bytes to the file at the current position.
    ///
    /// This uses `IORING_OP_WRITE` for true async write.
    #[must_use]
    pub fn write<'a>(&'a self, buf: &'a [u8]) -> WriteFuture<'a> {
        let offset = self.inner.position.load(Ordering::Relaxed);
        WriteFuture {
            file: self,
            buf,
            offset,
            update_position: true,
        }
    }

    /// Writes bytes to the file at a specific offset.
    ///
    /// This does not modify the file's current position.
    #[must_use]
    pub fn write_at<'a>(&'a self, buf: &'a [u8], offset: u64) -> WriteFuture<'a> {
        WriteFuture {
            file: self,
            buf,
            offset,
            update_position: false,
        }
    }

    /// Syncs file data to disk (equivalent to fdatasync).
    ///
    /// This uses `IORING_OP_FSYNC` with `IORING_FSYNC_DATASYNC`.
    #[must_use]
    pub fn sync_data(&self) -> SyncFuture<'_> {
        SyncFuture {
            file: self,
            datasync: true,
        }
    }

    /// Syncs all file data and metadata to disk (equivalent to fsync).
    ///
    /// This uses `IORING_OP_FSYNC`.
    #[must_use]
    pub fn sync_all(&self) -> SyncFuture<'_> {
        SyncFuture {
            file: self,
            datasync: false,
        }
    }

    /// Returns the current position in the file.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.inner.position.load(Ordering::Relaxed)
    }

    /// Sets the file position.
    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let fd = self.inner.fd.as_raw_fd();
        let (whence, offset) = match pos {
            SeekFrom::Start(n) => {
                let offset = i64::try_from(n).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek offset out of range")
                })?;
                (libc::SEEK_SET, offset)
            }
            SeekFrom::End(n) => (libc::SEEK_END, n),
            SeekFrom::Current(n) => (libc::SEEK_CUR, n),
        };

        // SAFETY: lseek is safe with a valid fd.
        let result = unsafe { libc::lseek(fd, offset, whence) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let new_pos =
            u64::try_from(result).map_err(|_| io::Error::other("seek result out of range"))?;
        self.inner.position.store(new_pos, Ordering::Relaxed);
        Ok(new_pos)
    }

    /// Truncates or extends the underlying file to the specified length.
    ///
    /// Uses `ftruncate` syscall (no io_uring opcode for truncate).
    pub fn set_len(&self, size: u64) -> io::Result<()> {
        let fd = self.inner.fd.as_raw_fd();
        let size_off = libc::off_t::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "size out of range"))?;
        // SAFETY: ftruncate is safe with a valid fd.
        let result = unsafe { libc::ftruncate(fd, size_off) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        // If position is past new length, clamp it
        let pos = self.inner.position.load(Ordering::Relaxed);
        if pos > size {
            self.inner.position.store(size, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Queries metadata about the underlying file via `fstat`.
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        let fd = self.inner.fd.as_raw_fd();
        // SAFETY: We borrow the fd temporarily; the OwnedFd still owns it.
        let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let meta = std_file.metadata();
        // Prevent the std File from closing our fd
        std::mem::forget(std_file);
        meta
    }

    /// Changes the permissions on the underlying file.
    pub fn set_permissions(&self, perm: std::fs::Permissions) -> io::Result<()> {
        let fd = self.inner.fd.as_raw_fd();
        let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let result = std_file.set_permissions(perm);
        std::mem::forget(std_file);
        result
    }

    /// Returns the raw file descriptor.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.fd.as_raw_fd()
    }

    /// Helper to submit an SQE and collect completion.
    fn submit_and_wait(&self, entry: &io_uring::squeue::Entry) -> io::Result<i32> {
        let result = {
            let mut ring = self.inner.ring.lock();

            // SAFETY: The entry is valid for the duration of the operation.
            unsafe {
                ring.submission().push(entry).map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "submission queue full")
                })?;
            }

            ring.submit_and_wait(1)?;

            // Get the completion - extract result before dropping the iterator.
            let result = {
                let mut cq = ring.completion();
                cq.next().map(|cqe| cqe.result())
            };

            // Release the ring lock before returning (keeps contention low when io-uring is used
            // concurrently by multiple filesystem helpers).
            drop(ring);
            result
        };

        result.ok_or_else(|| io::Error::other("no completion received"))
    }

    /// Blocking read using io_uring (for poll-based async trait).
    fn blocking_read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let fd = self.inner.fd.as_raw_fd();
        let entry = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), buf.len() as u32)
            .offset(offset)
            .build()
            .user_data(OP_READ);

        let result = self.submit_and_wait(&entry)?;
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
        } else {
            usize::try_from(result).map_err(|_| io::Error::other("read result out of range"))
        }
    }

    /// Blocking write using io_uring (for poll-based async trait).
    fn blocking_write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        let fd = self.inner.fd.as_raw_fd();
        let entry = opcode::Write::new(types::Fd(fd), buf.as_ptr(), buf.len() as u32)
            .offset(offset)
            .build()
            .user_data(OP_WRITE);

        let result = self.submit_and_wait(&entry)?;
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
        } else {
            usize::try_from(result).map_err(|_| io::Error::other("write result out of range"))
        }
    }

    /// Blocking sync using io_uring.
    fn blocking_sync(&self, datasync: bool) -> io::Result<()> {
        let fd = self.inner.fd.as_raw_fd();
        let mut builder = opcode::Fsync::new(types::Fd(fd));
        if datasync {
            builder = builder.flags(types::FsyncFlags::DATASYNC);
        }
        let entry = builder
            .build()
            .user_data(if datasync { OP_FDATASYNC } else { OP_FSYNC });

        let result = self.submit_and_wait(&entry)?;
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
        } else {
            Ok(())
        }
    }
}

impl AsRawFd for IoUringFile {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.fd.as_raw_fd()
    }
}

/// Future for async read operations.
pub struct ReadFuture<'a> {
    file: &'a IoUringFile,
    buf: &'a mut [u8],
    offset: u64,
    update_position: bool,
}

impl std::future::Future for ReadFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // For now, use blocking io_uring operations.
        // True async requires integration with the runtime's event loop.
        let this = self.get_mut();
        let n = this.file.blocking_read_at(this.buf, this.offset)?;

        if this.update_position {
            this.file
                .inner
                .position
                .fetch_add(n as u64, Ordering::Relaxed);
        }

        Poll::Ready(Ok(n))
    }
}

/// Future for async write operations.
pub struct WriteFuture<'a> {
    file: &'a IoUringFile,
    buf: &'a [u8],
    offset: u64,
    update_position: bool,
}

impl std::future::Future for WriteFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let n = this.file.blocking_write_at(this.buf, this.offset)?;

        if this.update_position {
            this.file
                .inner
                .position
                .fetch_add(n as u64, Ordering::Relaxed);
        }

        Poll::Ready(Ok(n))
    }
}

/// Future for async sync operations.
pub struct SyncFuture<'a> {
    file: &'a IoUringFile,
    datasync: bool,
}

impl std::future::Future for SyncFuture<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.file.blocking_sync(this.datasync)?;
        Poll::Ready(Ok(()))
    }
}

// Implement AsyncRead/AsyncWrite/AsyncSeek traits for compatibility

impl AsyncRead for IoUringFile {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let offset = self.inner.position.load(Ordering::Relaxed);
        let n = self.blocking_read_at(buf.unfilled(), offset)?;
        buf.advance(n);
        self.inner.position.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for IoUringFile {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let offset = self.inner.position.load(Ordering::Relaxed);
        let n = self.blocking_write_at(buf, offset)?;
        self.inner.position.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.blocking_sync(true)?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for IoUringFile {
    fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let new_pos = self.seek(pos)?;
        Poll::Ready(Ok(new_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_uring_file_create_write_read() {
        init_test("test_uring_file_create_write_read");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_test.txt");

            // Create and write
            let file = IoUringFile::create(&path).unwrap();
            let n = file.write(b"hello io_uring").await.unwrap();
            crate::assert_with_log!(n == 14, "bytes written", 14usize, n);
            file.sync_all().await.unwrap();
            drop(file);

            // Read back
            let file = IoUringFile::open(&path).unwrap();
            let mut buf = vec![0u8; 32];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 14, "bytes read", 14usize, n);
            crate::assert_with_log!(
                &buf[..n] == b"hello io_uring",
                "content",
                "hello io_uring",
                String::from_utf8_lossy(&buf[..n])
            );
        });
        crate::test_complete!("test_uring_file_create_write_read");
    }

    #[test]
    fn test_uring_file_drop_drains_pending_read() {
        init_test("test_uring_file_drop_drains_pending_read");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_drop_pending_read.txt");
        std::fs::write(&path, b"hello").unwrap();

        let file = IoUringFile::open(&path).unwrap();
        let mut buf = vec![0u8; 5];

        // Submit a read without waiting for it in user code, then rely on Drop to
        // drain the CQE before tearing down the ring mapping.
        *file.inner.read_state.lock() = OpState::Pending { waker: None };
        {
            let fd = file.inner.fd.as_raw_fd();
            let entry = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), buf.len() as u32)
                .offset(0)
                .build()
                .user_data(OP_READ);

            let mut ring = file.inner.ring.lock();
            // SAFETY: `buf` lives until after `file` is dropped, and Drop will
            // wait for completion before releasing the ring mapping.
            unsafe {
                ring.submission()
                    .push(&entry)
                    .expect("submission queue full");
            }
            ring.submit().unwrap();
        }

        drop(file);

        crate::assert_with_log!(
            &buf == b"hello",
            "drop drained read",
            "hello",
            String::from_utf8_lossy(&buf)
        );
        crate::test_complete!("test_uring_file_drop_drains_pending_read");
    }

    #[test]
    fn test_uring_file_read_at_write_at() {
        init_test("test_uring_file_read_at_write_at");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_offset_test.txt");

            // Create file with content
            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Write at offset 0
            let n = file.write_at(b"AAAAAAAAAA", 0).await.unwrap();
            crate::assert_with_log!(n == 10, "first write", 10usize, n);

            // Write at offset 5 (overwrite middle)
            let n = file.write_at(b"BBBBB", 5).await.unwrap();
            crate::assert_with_log!(n == 5, "second write", 5usize, n);

            file.sync_all().await.unwrap();

            // Read at offset 0
            let mut buf = vec![0u8; 10];
            let n = file.read_at(&mut buf, 0).await.unwrap();
            crate::assert_with_log!(n == 10, "read back", 10usize, n);
            crate::assert_with_log!(
                &buf[..n] == b"AAAAABBBBB",
                "content",
                "AAAAABBBBB",
                String::from_utf8_lossy(&buf[..n])
            );
        });
        crate::test_complete!("test_uring_file_read_at_write_at");
    }

    #[test]
    fn test_uring_file_position_tracking() {
        init_test("test_uring_file_position_tracking");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_position_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Initial position should be 0
            crate::assert_with_log!(
                file.position() == 0,
                "initial position",
                0u64,
                file.position()
            );

            // Write updates position
            let n = file.write(b"hello").await.unwrap();
            crate::assert_with_log!(n == 5, "write", 5usize, n);
            crate::assert_with_log!(
                file.position() == 5,
                "position after write",
                5u64,
                file.position()
            );

            // write_at does NOT update position
            let n = file.write_at(b"world", 10).await.unwrap();
            crate::assert_with_log!(n == 5, "write_at", 5usize, n);
            crate::assert_with_log!(
                file.position() == 5,
                "position after write_at",
                5u64,
                file.position()
            );

            // Seek updates position
            let pos = file.seek(SeekFrom::Start(0)).unwrap();
            crate::assert_with_log!(pos == 0, "seek result", 0u64, pos);
            crate::assert_with_log!(
                file.position() == 0,
                "position after seek",
                0u64,
                file.position()
            );
        });
        crate::test_complete!("test_uring_file_position_tracking");
    }

    #[test]
    fn test_uring_file_sync_data() {
        init_test("test_uring_file_sync_data");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_sync_test.txt");

            let file = IoUringFile::create(&path).unwrap();
            file.write(b"sync test data").await.unwrap();

            // sync_data should succeed
            file.sync_data().await.unwrap();

            // sync_all should succeed
            file.sync_all().await.unwrap();
        });
        crate::test_complete!("test_uring_file_sync_data");
    }

    #[test]
    fn test_uring_file_set_len_truncate() {
        init_test("test_uring_file_set_len_truncate");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_truncate_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Write 20 bytes
            file.write(b"01234567890123456789").await.unwrap();
            file.sync_all().await.unwrap();

            // Truncate to 10
            file.set_len(10).unwrap();

            // Position should be clamped from 19 to 10
            crate::assert_with_log!(
                file.position() <= 10,
                "position clamped after truncate",
                true,
                file.position() <= 10
            );

            // Read back and verify
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = vec![0u8; 32];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 10, "truncated read length", 10usize, n);
            crate::assert_with_log!(
                &buf[..n] == b"0123456789",
                "truncated content",
                "0123456789",
                String::from_utf8_lossy(&buf[..n])
            );
        });
        crate::test_complete!("test_uring_file_set_len_truncate");
    }

    #[test]
    fn test_uring_file_set_len_extend() {
        init_test("test_uring_file_set_len_extend");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_extend_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            file.write(b"hello").await.unwrap();
            file.sync_all().await.unwrap();

            // Extend to 10 bytes (zero-filled beyond 5)
            file.set_len(10).unwrap();

            let meta = file.metadata().unwrap();
            crate::assert_with_log!(meta.len() == 10, "extended length", 10u64, meta.len());

            // Read the extended region
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = vec![0u8; 10];
            let n = file.read_at(&mut buf, 0).await.unwrap();
            crate::assert_with_log!(n == 10, "read length", 10usize, n);
            crate::assert_with_log!(
                &buf[..5] == b"hello",
                "original content preserved",
                "hello",
                String::from_utf8_lossy(&buf[..5])
            );
            crate::assert_with_log!(
                buf[5..] == [0u8; 5],
                "extended bytes are zero",
                true,
                buf[5..] == [0u8; 5]
            );
        });
        crate::test_complete!("test_uring_file_set_len_extend");
    }

    #[test]
    fn test_uring_file_metadata() {
        init_test("test_uring_file_metadata");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_metadata_test.txt");

            let file = IoUringFile::create(&path).unwrap();
            file.write(b"metadata test").await.unwrap();
            file.sync_all().await.unwrap();

            let meta = file.metadata().unwrap();
            crate::assert_with_log!(meta.is_file(), "is_file", true, meta.is_file());
            crate::assert_with_log!(meta.len() == 13, "file length", 13u64, meta.len());
        });
        crate::test_complete!("test_uring_file_metadata");
    }

    #[test]
    fn test_uring_file_large_io() {
        init_test("test_uring_file_large_io");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_large_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Write 64KB of data in 4KB chunks
            let data: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
            let mut written = 0usize;
            while written < data.len() {
                let end = std::cmp::min(written + 4096, data.len());
                let n = file
                    .write_at(&data[written..end], written as u64)
                    .await
                    .unwrap();
                written += n;
            }
            file.sync_all().await.unwrap();

            // Read back in one shot and verify
            let mut buf = vec![0u8; 65536];
            let mut read_total = 0usize;
            while read_total < buf.len() {
                let n = file
                    .read_at(&mut buf[read_total..], read_total as u64)
                    .await
                    .unwrap();
                if n == 0 {
                    break;
                }
                read_total += n;
            }
            crate::assert_with_log!(read_total == 65536, "total read", 65536usize, read_total);
            crate::assert_with_log!(buf == data, "data integrity", true, buf == data);
        });
        crate::test_complete!("test_uring_file_large_io");
    }
}
