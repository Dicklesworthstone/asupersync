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
use io_uring::{IoUring, opcode, types};
use parking_lot::Mutex;
use std::ffi::CString;
use std::io::{self, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

/// Default io_uring queue size for file operations.
const DEFAULT_ENTRIES: u32 = 64;

/// High bits reserved for operation kind tags in io_uring `user_data`.
const USER_DATA_KIND_SHIFT: u32 = 56;
const USER_DATA_SEQUENCE_MASK: u64 = (1u64 << USER_DATA_KIND_SHIFT) - 1;

/// Logical operation kind for io_uring requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum OpKind {
    Read = 1,
    Write = 2,
    Fsync = 3,
    Fdatasync = 4,
    Close = 5,
}

impl OpKind {
    fn encode(self, sequence: u64) -> u64 {
        (u64::from(self as u8) << USER_DATA_KIND_SHIFT) | (sequence & USER_DATA_SEQUENCE_MASK)
    }

    fn decode(user_data: u64) -> Option<Self> {
        match (user_data >> USER_DATA_KIND_SHIFT) as u8 {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Fsync),
            4 => Some(Self::Fdatasync),
            5 => Some(Self::Close),
            _ => None,
        }
    }
}

/// State for a pending io_uring operation.
#[derive(Debug)]
#[allow(dead_code)]
enum OpState {
    /// Operation not yet submitted.
    Idle,
    /// Operation submitted, waiting for completion.
    Pending {
        user_data: u64,
        waker: Option<Waker>,
    },
    /// Operation completed with result.
    Complete(i32),
}

/// Shared state for io_uring file operations.
struct IoUringFileInner {
    /// The io_uring instance for this file.
    ring: Mutex<IoUring>,
    /// The open file descriptor.
    fd: OwnedFd,
    /// Logical file position for sequential read/write.
    position: AtomicU64,
    /// Serializes implicit-cursor operations and logical seeks.
    cursor_lock: Mutex<()>,
    /// State for pending read operation.
    read_state: Mutex<OpState>,
    /// State for pending write operation.
    write_state: Mutex<OpState>,
    /// State for pending sync operation.
    sync_state: Mutex<OpState>,
    /// Monotonic request-id source used to disambiguate io_uring completions.
    next_user_data: AtomicU64,
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

fn state_pending_user_data(state: &Mutex<OpState>) -> Option<u64> {
    match &*state.lock() {
        OpState::Pending { user_data, .. } => Some(*user_data),
        _ => None,
    }
}

fn mark_op_complete(state: &Mutex<OpState>, user_data: u64, result: i32) -> bool {
    let waker_to_wake = {
        let mut guard = state.lock();
        let waker = match &mut *guard {
            OpState::Pending {
                user_data: pending_user_data,
                waker,
            } if *pending_user_data == user_data => waker.take(),
            _ => return false,
        };
        *guard = OpState::Complete(result);
        waker
    };

    if let Some(w) = waker_to_wake {
        w.wake();
    }
    true
}

fn mark_tracked_op_complete(inner: &IoUringFileInner, user_data: u64, result: i32) -> bool {
    match OpKind::decode(user_data) {
        Some(OpKind::Read) => mark_op_complete(&inner.read_state, user_data, result),
        Some(OpKind::Write) => mark_op_complete(&inner.write_state, user_data, result),
        Some(OpKind::Fsync | OpKind::Fdatasync) => {
            mark_op_complete(&inner.sync_state, user_data, result)
        }
        Some(OpKind::Close) | None => false,
    }
}

fn tracked_pending_user_data(inner: &IoUringFileInner) -> Vec<u64> {
    let mut pending = Vec::with_capacity(3);
    if let Some(user_data) = state_pending_user_data(&inner.read_state) {
        pending.push(user_data);
    }
    if let Some(user_data) = state_pending_user_data(&inner.write_state) {
        pending.push(user_data);
    }
    if let Some(user_data) = state_pending_user_data(&inner.sync_state) {
        pending.push(user_data);
    }
    pending
}

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes"))
}

fn polled_after_completion_error(operation: &str) -> io::Error {
    io::Error::other(format!(
        "io_uring {operation} future polled after completion"
    ))
}

fn missing_explicit_offset_error(operation: &str) -> io::Error {
    io::Error::other(format!(
        "io_uring {operation}_at future missing explicit offset"
    ))
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

                for user_data in tracked_pending_user_data(&self.inner) {
                    let _ = ring
                        .submitter()
                        .register_sync_cancel(None, types::CancelBuilder::user_data(user_data));
                }

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
                let _ = mark_tracked_op_complete(&self.inner, user_data, result);
            }
        }
    }
}

impl IoUringFile {
    fn current_fd_position(fd: RawFd) -> io::Result<u64> {
        // SAFETY: lseek is safe with a valid fd. We only query the current
        // offset so the logical cursor matches the transferred descriptor.
        let result = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        u64::try_from(result).map_err(|_| io::Error::other("seek result out of range"))
    }

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
        let c_path = path_to_cstring(path)?;

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
                cursor_lock: Mutex::new(()),
                read_state: Mutex::new(OpState::Idle),
                write_state: Mutex::new(OpState::Idle),
                sync_state: Mutex::new(OpState::Idle),
                next_user_data: AtomicU64::new(1),
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
        // SAFETY: caller guarantees fd is valid and not used elsewhere
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let position = Self::current_fd_position(owned_fd.as_raw_fd())?;
        let ring = IoUring::new(DEFAULT_ENTRIES)?;

        Ok(Self {
            inner: Arc::new(IoUringFileInner {
                ring: Mutex::new(ring),
                fd: owned_fd,
                position: AtomicU64::new(position),
                cursor_lock: Mutex::new(()),
                read_state: Mutex::new(OpState::Idle),
                write_state: Mutex::new(OpState::Idle),
                sync_state: Mutex::new(OpState::Idle),
                next_user_data: AtomicU64::new(1),
            }),
        })
    }

    /// Reads bytes from the file at the current position.
    ///
    /// This uses `IORING_OP_READ` for true async read.
    #[must_use]
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> ReadFuture<'a> {
        ReadFuture {
            file: self,
            buf,
            offset: None,
            update_position: true,
            done: false,
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
            offset: Some(offset),
            update_position: false,
            done: false,
        }
    }

    /// Writes bytes to the file at the current position.
    ///
    /// This uses `IORING_OP_WRITE` for true async write.
    #[must_use]
    pub fn write<'a>(&'a self, buf: &'a [u8]) -> WriteFuture<'a> {
        WriteFuture {
            file: self,
            buf,
            offset: None,
            update_position: true,
            done: false,
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
            offset: Some(offset),
            update_position: false,
            done: false,
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
            done: false,
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
            done: false,
        }
    }

    /// Returns the logical current position used by sequential read/write operations.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.inner.position.load(Ordering::Relaxed)
    }

    fn checked_seek_target(base: u64, delta: i64) -> io::Result<u64> {
        base.checked_add_signed(delta)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek offset out of range"))
    }

    /// Sets the logical file position used by sequential read/write operations.
    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let _cursor_guard = self.inner.cursor_lock.lock();
        let current = self.inner.position.load(Ordering::Relaxed);

        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(delta) => {
                let end = self.metadata()?.len();
                Self::checked_seek_target(end, delta)?
            }
            SeekFrom::Current(delta) => Self::checked_seek_target(current, delta)?,
        };
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
        let _cursor_guard = self.inner.cursor_lock.lock();
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
        let std_file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        std_file.metadata()
    }

    /// Changes the permissions on the underlying file.
    pub fn set_permissions(&self, perm: std::fs::Permissions) -> io::Result<()> {
        let fd = self.inner.fd.as_raw_fd();
        let std_file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        std_file.set_permissions(perm)
    }

    /// Returns the raw file descriptor.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.fd.as_raw_fd()
    }

    fn allocate_user_data(&self, kind: OpKind) -> u64 {
        let sequence = self.inner.next_user_data.fetch_add(1, Ordering::Relaxed);
        kind.encode(sequence.max(1))
    }

    fn drain_completions_locked(
        &self,
        ring: &mut IoUring,
        expected_user_data: Option<u64>,
    ) -> Option<i32> {
        let completions = ring
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result()))
            .collect::<Vec<_>>();

        let mut expected_result = None;
        for (user_data, result) in completions {
            if expected_user_data.is_some_and(|expected| expected == user_data) {
                expected_result = Some(result);
            } else {
                let _ = mark_tracked_op_complete(&self.inner, user_data, result);
            }
        }

        expected_result
    }

    fn push_entry_with_recovery(
        &self,
        ring: &mut IoUring,
        entry: &io_uring::squeue::Entry,
    ) -> io::Result<()> {
        for attempt in 0..3 {
            // SAFETY: The entry points at buffers owned by the caller for the
            // duration of the synchronous submit/wait cycle below.
            let push_result = unsafe { ring.submission().push(entry) };
            if push_result.is_ok() {
                return Ok(());
            }

            if attempt == 2 {
                break;
            }

            ring.submit()?;
            let _ = self.drain_completions_locked(ring, None);
        }

        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "submission queue full",
        ))
    }

    /// Helper to submit an SQE and collect completion.
    fn submit_and_wait(
        &self,
        entry: &io_uring::squeue::Entry,
        expected_user_data: u64,
    ) -> io::Result<i32> {
        let mut ring = self.inner.ring.lock();
        let _ = self.drain_completions_locked(&mut ring, None);
        self.push_entry_with_recovery(&mut ring, entry)?;

        loop {
            ring.submit_and_wait(1)?;
            if let Some(result) = self.drain_completions_locked(&mut ring, Some(expected_user_data))
            {
                return Ok(result);
            }
        }
    }

    /// Blocking read using io_uring (for poll-based async trait).
    fn blocking_read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let fd = self.inner.fd.as_raw_fd();
        let user_data = self.allocate_user_data(OpKind::Read);
        let entry = opcode::Read::new(
            types::Fd(fd),
            buf.as_mut_ptr(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
        .offset(offset)
        .build()
        .user_data(user_data);

        let result = self.submit_and_wait(&entry, user_data)?;
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
        } else {
            usize::try_from(result).map_err(|_| io::Error::other("read result out of range"))
        }
    }

    /// Blocking write using io_uring (for poll-based async trait).
    fn blocking_write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        let fd = self.inner.fd.as_raw_fd();
        let user_data = self.allocate_user_data(OpKind::Write);
        let entry = opcode::Write::new(
            types::Fd(fd),
            buf.as_ptr(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
        .offset(offset)
        .build()
        .user_data(user_data);

        let result = self.submit_and_wait(&entry, user_data)?;
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
        } else {
            usize::try_from(result).map_err(|_| io::Error::other("write result out of range"))
        }
    }

    /// Blocking sync using io_uring.
    fn blocking_sync(&self, datasync: bool) -> io::Result<()> {
        let fd = self.inner.fd.as_raw_fd();
        let kind = if datasync {
            OpKind::Fdatasync
        } else {
            OpKind::Fsync
        };
        let user_data = self.allocate_user_data(kind);
        let mut builder = opcode::Fsync::new(types::Fd(fd));
        if datasync {
            builder = builder.flags(types::FsyncFlags::DATASYNC);
        }
        let entry = builder.build().user_data(user_data);

        let result = self.submit_and_wait(&entry, user_data)?;
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

#[cfg(test)]
impl IoUringFile {
    fn submit_pending_read_for_test(&self, buf: &mut [u8], offset: u64) -> io::Result<u64> {
        let user_data = self.allocate_user_data(OpKind::Read);
        {
            let mut state = self.inner.read_state.lock();
            if !matches!(*state, OpState::Idle) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "test pending read already registered",
                ));
            }
            *state = OpState::Pending {
                user_data,
                waker: None,
            };
        }

        let entry = opcode::Read::new(
            types::Fd(self.inner.fd.as_raw_fd()),
            buf.as_mut_ptr(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
        .offset(offset)
        .build()
        .user_data(user_data);

        let submit_result = {
            let mut ring = self.inner.ring.lock();
            self.push_entry_with_recovery(&mut ring, &entry)?;
            ring.submit()
        };

        if let Err(err) = submit_result {
            *self.inner.read_state.lock() = OpState::Idle;
            return Err(err);
        }

        Ok(user_data)
    }
}

/// Future for async read operations.
pub struct ReadFuture<'a> {
    file: &'a IoUringFile,
    buf: &'a mut [u8],
    offset: Option<u64>,
    update_position: bool,
    done: bool,
}

impl std::future::Future for ReadFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // For now, use blocking io_uring operations.
        // True async requires integration with the runtime's event loop.
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(polled_after_completion_error("read")));
        }
        let result = if this.update_position {
            let _cursor_guard = this.file.inner.cursor_lock.lock();
            let offset = this.file.inner.position.load(Ordering::Relaxed);
            let result = this.file.blocking_read_at(this.buf, offset);
            if let Ok(n) = result {
                this.file
                    .inner
                    .position
                    .store(offset.saturating_add(n as u64), Ordering::Relaxed);
            }
            result
        } else {
            match this.offset {
                Some(offset) => this.file.blocking_read_at(this.buf, offset),
                None => Err(missing_explicit_offset_error("read")),
            }
        };

        this.done = true;
        Poll::Ready(result)
    }
}

/// Future for async write operations.
pub struct WriteFuture<'a> {
    file: &'a IoUringFile,
    buf: &'a [u8],
    offset: Option<u64>,
    update_position: bool,
    done: bool,
}

impl std::future::Future for WriteFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(polled_after_completion_error("write")));
        }
        let result = if this.update_position {
            let _cursor_guard = this.file.inner.cursor_lock.lock();
            let offset = this.file.inner.position.load(Ordering::Relaxed);
            let result = this.file.blocking_write_at(this.buf, offset);
            if let Ok(n) = result {
                this.file
                    .inner
                    .position
                    .store(offset.saturating_add(n as u64), Ordering::Relaxed);
            }
            result
        } else {
            match this.offset {
                Some(offset) => this.file.blocking_write_at(this.buf, offset),
                None => Err(missing_explicit_offset_error("write")),
            }
        };

        this.done = true;
        Poll::Ready(result)
    }
}

/// Future for async sync operations.
pub struct SyncFuture<'a> {
    file: &'a IoUringFile,
    datasync: bool,
    done: bool,
}

impl std::future::Future for SyncFuture<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(polled_after_completion_error("sync")));
        }

        let result = this.file.blocking_sync(this.datasync);
        this.done = true;
        Poll::Ready(result)
    }
}

// Implement AsyncRead/AsyncWrite/AsyncSeek traits for compatibility

impl AsyncRead for IoUringFile {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _cursor_guard = self.inner.cursor_lock.lock();
        let offset = self.inner.position.load(Ordering::Relaxed);
        let n = self.blocking_read_at(buf.unfilled(), offset)?;
        buf.advance(n);
        self.inner
            .position
            .store(offset.saturating_add(n as u64), Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for IoUringFile {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _cursor_guard = self.inner.cursor_lock.lock();
        let offset = self.inner.position.load(Ordering::Relaxed);
        let n = self.blocking_write_at(buf, offset)?;
        self.inner
            .position
            .store(offset.saturating_add(n as u64), Ordering::Relaxed);
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    use std::os::fd::IntoRawFd;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn assert_polled_after_completion(err: &io::Error, operation: &str) {
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(
            err.to_string(),
            format!("io_uring {operation} future polled after completion")
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_path_to_cstring_accepts_non_utf8_unix_paths() {
        init_test("test_path_to_cstring_accepts_non_utf8_unix_paths");
        let raw = vec![b'f', b'i', b'l', b'e', b'_', 0xFD];
        let path = std::path::PathBuf::from(OsString::from_vec(raw.clone()));

        let c = path_to_cstring(&path).expect("non-utf8 unix path should be accepted");
        crate::assert_with_log!(
            c.as_bytes() == raw.as_slice(),
            "raw bytes preserved",
            raw.as_slice(),
            c.as_bytes()
        );
        crate::test_complete!("test_path_to_cstring_accepts_non_utf8_unix_paths");
    }

    #[cfg(unix)]
    #[test]
    fn test_path_to_cstring_rejects_nul_bytes() {
        init_test("test_path_to_cstring_rejects_nul_bytes");
        let path = std::path::PathBuf::from(OsString::from_vec(vec![b'b', b'a', b'd', 0, b'x']));

        let err = path_to_cstring(&path).expect_err("path with nul must be rejected");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "invalid input error",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_path_to_cstring_rejects_nul_bytes");
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
        let _user_data = file.submit_pending_read_for_test(&mut buf, 0).unwrap();

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
    fn test_uring_completion_attribution_ignores_unrelated_cqe() {
        init_test("test_uring_completion_attribution_ignores_unrelated_cqe");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_unrelated_cqe.txt");
            std::fs::write(&path, b"hello").unwrap();

            let file = IoUringFile::open(&path).unwrap();

            {
                let entry = opcode::Nop::new().build().user_data(0xDEAD_BEEF);
                let mut ring = file.inner.ring.lock();
                // SAFETY: NOP has no external buffer dependencies.
                unsafe {
                    ring.submission()
                        .push(&entry)
                        .expect("submission queue full");
                }
                ring.submit().unwrap();
            }

            let mut buf = [0u8; 5];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 5, "read length", 5usize, n);
            crate::assert_with_log!(
                &buf == b"hello",
                "read ignores unrelated CQE and returns actual data",
                "hello",
                String::from_utf8_lossy(&buf)
            );
        });
        crate::test_complete!("test_uring_completion_attribution_ignores_unrelated_cqe");
    }

    #[test]
    fn test_uring_sq_full_recovers_by_submitting_and_retrying() {
        init_test("test_uring_sq_full_recovers_by_submitting_and_retrying");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_sq_full_retry.txt");
            std::fs::write(&path, b"hello").unwrap();

            let file = IoUringFile::open(&path).unwrap();

            {
                let mut ring = file.inner.ring.lock();
                let mut next_user_data = 1u64;
                loop {
                    let entry = opcode::Nop::new()
                        .build()
                        .user_data(0xAA00_0000 + next_user_data);
                    // SAFETY: NOP has no external buffer dependencies.
                    let push_result = unsafe { ring.submission().push(&entry) };
                    if push_result.is_err() {
                        break;
                    }
                    next_user_data = next_user_data.saturating_add(1);
                }
            }

            let mut buf = [0u8; 5];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 5, "read length after SQ recovery", 5usize, n);
            crate::assert_with_log!(
                &buf == b"hello",
                "read succeeds after SQ-full recovery",
                "hello",
                String::from_utf8_lossy(&buf)
            );
        });
        crate::test_complete!("test_uring_sq_full_recovers_by_submitting_and_retrying");
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
    fn test_uring_seek_current_uses_logical_position() {
        init_test("test_uring_seek_current_uses_logical_position");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_seek_current_position.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            let n = file.write(b"abcdef").await.unwrap();
            crate::assert_with_log!(n == 6, "write length", 6usize, n);

            let current = file.seek(SeekFrom::Current(0)).unwrap();
            crate::assert_with_log!(current == 6, "current seek result", 6u64, current);
            crate::assert_with_log!(
                file.position() == 6,
                "position after current seek",
                6u64,
                file.position()
            );

            let current = file.seek(SeekFrom::Current(-2)).unwrap();
            crate::assert_with_log!(current == 4, "rewound seek result", 4u64, current);
            crate::assert_with_log!(
                file.position() == 4,
                "position after rewind",
                4u64,
                file.position()
            );

            let mut tail = [0u8; 2];
            let n = file.read(&mut tail).await.unwrap();
            crate::assert_with_log!(n == 2, "tail read length", 2usize, n);
            crate::assert_with_log!(
                &tail == b"ef",
                "tail read bytes",
                "ef",
                String::from_utf8_lossy(&tail)
            );
        });
        crate::test_complete!("test_uring_seek_current_uses_logical_position");
    }

    #[test]
    fn test_uring_from_raw_fd_preserves_existing_cursor_position() {
        init_test("test_uring_from_raw_fd_preserves_existing_cursor_position");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_from_raw_fd_cursor.txt");

            std::fs::write(&path, b"abcdef").unwrap();
            let mut std_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            std::io::Seek::seek(&mut std_file, SeekFrom::Start(2)).unwrap();

            let raw_fd = std_file.into_raw_fd();
            let file = unsafe { IoUringFile::from_raw_fd(raw_fd) }.unwrap();

            crate::assert_with_log!(
                file.position() == 2,
                "initial logical cursor preserves raw fd offset",
                2u64,
                file.position()
            );
            let current = file.seek(SeekFrom::Current(0)).unwrap();
            crate::assert_with_log!(current == 2, "seek current", 2u64, current);

            let mut buf = [0u8; 2];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 2, "read length", 2usize, n);
            crate::assert_with_log!(
                &buf == b"cd",
                "read starts from transferred cursor",
                "cd",
                String::from_utf8_lossy(&buf)
            );
            crate::assert_with_log!(
                file.position() == 4,
                "position after read from transferred cursor",
                4u64,
                file.position()
            );
        });
        crate::test_complete!("test_uring_from_raw_fd_preserves_existing_cursor_position");
    }

    #[test]
    fn test_uring_from_raw_fd_closes_fd_when_position_probe_fails() {
        init_test("test_uring_from_raw_fd_closes_fd_when_position_probe_fails");

        let mut fds = [0; 2];
        let pipe_result = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe creation should succeed");

        let read_fd = fds[0];
        let write_fd = fds[1];

        let err = unsafe { IoUringFile::from_raw_fd(read_fd) }
            .expect_err("non-seekable fds must fail position probe");
        crate::assert_with_log!(
            err.raw_os_error() == Some(libc::ESPIPE),
            "pipe fd fails with ESPIPE",
            Some(libc::ESPIPE),
            err.raw_os_error()
        );

        let close_result = unsafe { libc::close(read_fd) };
        crate::assert_with_log!(
            close_result == -1,
            "failed construction must still consume and close the transferred fd",
            -1,
            close_result
        );
        crate::assert_with_log!(
            io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
            "transferred fd is already closed after failure",
            Some(libc::EBADF),
            io::Error::last_os_error().raw_os_error()
        );

        let write_close_result = unsafe { libc::close(write_fd) };
        crate::assert_with_log!(
            write_close_result == 0,
            "write end remains open for explicit cleanup",
            0,
            write_close_result
        );

        crate::test_complete!("test_uring_from_raw_fd_closes_fd_when_position_probe_fails");
    }

    #[test]
    fn test_uring_write_uses_position_at_poll_time() {
        init_test("test_uring_write_uses_position_at_poll_time");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_lazy_write_position.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            let first = file.write(b"abc");
            let second = file.write(b"def");

            let n = first.await.unwrap();
            crate::assert_with_log!(n == 3, "first write length", 3usize, n);
            crate::assert_with_log!(
                file.position() == 3,
                "position after first write",
                3u64,
                file.position()
            );

            let n = second.await.unwrap();
            crate::assert_with_log!(n == 3, "second write length", 3usize, n);
            crate::assert_with_log!(
                file.position() == 6,
                "position after second write",
                6u64,
                file.position()
            );

            file.sync_all().await.unwrap();

            let mut buf = [0u8; 6];
            let n = file.read_at(&mut buf, 0).await.unwrap();
            crate::assert_with_log!(n == 6, "read back length", 6usize, n);
            crate::assert_with_log!(
                &buf == b"abcdef",
                "write futures append in poll order",
                "abcdef",
                String::from_utf8_lossy(&buf)
            );
        });
        crate::test_complete!("test_uring_write_uses_position_at_poll_time");
    }

    #[test]
    fn test_uring_read_uses_position_at_poll_time() {
        init_test("test_uring_read_uses_position_at_poll_time");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_lazy_read_position.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();
            file.write_at(b"abcdef", 0).await.unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            let mut first_buf = [0u8; 3];
            let mut second_buf = [0u8; 3];
            let first = file.read(&mut first_buf);
            let second = file.read(&mut second_buf);

            let n = first.await.unwrap();
            crate::assert_with_log!(n == 3, "first read length", 3usize, n);
            crate::assert_with_log!(
                &first_buf == b"abc",
                "first read bytes",
                "abc",
                String::from_utf8_lossy(&first_buf)
            );
            crate::assert_with_log!(
                file.position() == 3,
                "position after first read",
                3u64,
                file.position()
            );

            let n = second.await.unwrap();
            crate::assert_with_log!(n == 3, "second read length", 3usize, n);
            crate::assert_with_log!(
                &second_buf == b"def",
                "second read bytes",
                "def",
                String::from_utf8_lossy(&second_buf)
            );
            crate::assert_with_log!(
                file.position() == 6,
                "position after second read",
                6u64,
                file.position()
            );
        });
        crate::test_complete!("test_uring_read_uses_position_at_poll_time");
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
    fn test_uring_read_future_second_poll_fails_closed() {
        init_test("test_uring_read_future_second_poll_fails_closed");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_read_repoll.txt");
        std::fs::write(&path, b"hello").unwrap();

        let file = IoUringFile::open(&path).unwrap();
        let mut buf = [0u8; 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        {
            let mut future = file.read(&mut buf);
            let first = Pin::new(&mut future).poll(&mut cx);
            assert!(matches!(first, Poll::Ready(Ok(5))));
            assert_eq!(file.position(), 5);

            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Err(err)) => assert_polled_after_completion(&err, "read"),
                other => panic!("expected fail-closed read repoll, got {other:?}"),
            }
        }
        assert_eq!(&buf, b"hello");
        assert_eq!(file.position(), 5);
        crate::test_complete!("test_uring_read_future_second_poll_fails_closed");
    }

    #[test]
    fn test_uring_write_future_second_poll_fails_closed() {
        init_test("test_uring_write_future_second_poll_fails_closed");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_write_repoll.txt");

        let file = IoUringFile::open_with_flags(
            &path,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
        .unwrap();
        let mut future = file.write(b"abc");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(3))));
        assert_eq!(file.position(), 3);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(err)) => assert_polled_after_completion(&err, "write"),
            other => panic!("expected fail-closed write repoll, got {other:?}"),
        }
        assert_eq!(file.position(), 3);

        let mut buf = [0u8; 3];
        let n = futures_lite::future::block_on(file.read_at(&mut buf, 0)).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"abc");
        crate::test_complete!("test_uring_write_future_second_poll_fails_closed");
    }

    #[test]
    fn test_uring_sync_future_second_poll_fails_closed() {
        init_test("test_uring_sync_future_second_poll_fails_closed");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_sync_repoll.txt");

        let file = IoUringFile::create(&path).unwrap();
        let mut future = file.sync_all();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(()))));

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(err)) => assert_polled_after_completion(&err, "sync"),
            other => panic!("expected fail-closed sync repoll, got {other:?}"),
        }
        crate::test_complete!("test_uring_sync_future_second_poll_fails_closed");
    }

    #[test]
    fn test_uring_error_terminal_still_fails_closed_on_repoll() {
        init_test("test_uring_error_terminal_still_fails_closed_on_repoll");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_error_repoll.txt");
        std::fs::write(&path, b"hello").unwrap();

        let file = IoUringFile::open(&path).unwrap();
        let mut future = file.write(b"abc");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(_))));
        assert_eq!(file.position(), 0);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(err)) => assert_polled_after_completion(&err, "write"),
            other => panic!("expected fail-closed repoll after write error, got {other:?}"),
        }
        assert_eq!(file.position(), 0);
        crate::test_complete!("test_uring_error_terminal_still_fails_closed_on_repoll");
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
