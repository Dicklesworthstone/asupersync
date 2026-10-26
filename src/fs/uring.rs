//! io_uring-backed async file operations for Linux.
//!
//! This module uses io_uring's `READ`, `WRITE`, and `FSYNC` opcodes. The async
//! traits offload terminal-completion waits to the inherited blocking pool;
//! the synchronous constructors and borrowed operation futures retain their
//! synchronous completion boundary. An absent or rejecting pool uses the inline
//! fallback provided by ordinary filesystem I/O.
//!
//! # Platform Requirements
//!
//! - Linux kernel 5.6+ (for full feature set)
//! - `io-uring` feature enabled in Cargo.toml
//!
//! # Cancel Safety
//!
//! - `open`/`create`/`open_with_flags`: synchronous constructors; any create or
//!   truncate effect completes before the function returns
//! - `read`/`read_at`/`write`/`write_at` and `sync_data`/`sync_all`: lazy
//!   futures whose poll drives one request through its terminal completion and
//!   returns `Ready`; dropping an unpolled future has no effect, and async
//!   cancellation cannot interleave inside that synchronous poll
//! - tracked operations used by teardown tests: cancellation is only a request;
//!   drop drains their terminal completions before releasing kernel-owned data
//! - async traits: owned buffers and file state survive a dropped borrowing
//!   future. A retry collects the retained operation; interleaved reads and
//!   flushes preserve write credit, and smaller reads retain unread bytes.
//!   Other trait operations also preserve completed seek results, so retrying
//!   a relative seek does not move the cursor twice.
//!   Synchronous cursor and data operations return `WouldBlock` until a retained
//!   trait operation has been collected. Polling the original trait operation
//!   or `poll_flush` collects it. An explicit seek or a different write starts
//!   a new write sequence, so identical bytes after a seek are written again.

#![cfg(all(target_os = "linux", feature = "io-uring"))]
#![allow(unsafe_code)]

use crate::fs::metadata::{Metadata, Permissions};
use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use io_uring::{IoUring, opcode, types};
use parking_lot::Mutex;
use std::ffi::CString;
use std::future::Future;
use std::io::{self, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

/// Default io_uring queue size for file operations.
const DEFAULT_ENTRIES: u32 = 64;

/// High bits reserved for operation kind tags in io_uring `user_data`.
const USER_DATA_KIND_SHIFT: u32 = 56;
const USER_DATA_SEQUENCE_MASK: u64 = (1u64 << USER_DATA_KIND_SHIFT).saturating_sub(1);

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

    fn from_user_data(user_data: u64) -> Option<Self> {
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

/// An io_uring-backed file with asynchronous I/O traits on Linux.
///
/// The traits retain bounded owned buffers and use the inherited blocking
/// pool to wait for terminal kernel completion. The borrowed operation futures
/// keep their synchronous poll behavior. Finish a pending trait operation before
/// mixing in synchronous cursor or data operations; otherwise they return
/// [`io::ErrorKind::WouldBlock`].
///
/// # Example
///
/// ```no_run
/// use asupersync::fs::uring::IoUringFile;
///
/// async fn example() -> std::io::Result<()> {
///     let file = IoUringFile::open("/tmp/test.txt")?; // `open` is synchronous
///     let mut buf = vec![0u8; 1024];
///     let n = file.read(&mut buf).await?;
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct IoUringFile {
    inner: Arc<IoUringFileInner>,
    trait_io: Mutex<TraitIoState>,
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
    match OpKind::from_user_data(user_data) {
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

/// Drive a published SQE until its terminal completion has been observed.
///
/// Once an SQE is visible in the submission queue, a syscall error is not a
/// lifetime boundary: the kernel may own the request already, or the SQE may
/// remain queued for a later submission. Only a completion lets a caller
/// release memory referenced by the SQE. A permanently broken ring can
/// therefore block this loop indefinitely; that liveness loss is preferable
/// to returning while the kernel may still dereference caller memory.
fn wait_until_submitted_completion<T>(
    mut wait_and_drain: impl FnMut() -> (io::Result<usize>, Option<T>),
) -> T {
    loop {
        let (_wait_result, completion) = wait_and_drain();
        if let Some(completion) = completion {
            return completion;
        }

        // Retrying is intentionally fail-closed. Returning an error here
        // could release a borrowed buffer while the kernel still references
        // it. Yield whenever a cycle makes no terminal progress so an
        // anomalous successful zero-result cannot become a hot loop either.
        std::thread::yield_now();
    }
}

fn drain_tracked_until_quiescent(
    mut is_pending: impl FnMut() -> bool,
    mut next_completions: impl FnMut() -> Vec<(u64, i32)>,
    mut record_completion: impl FnMut(u64, i32),
) {
    while is_pending() {
        for (user_data, result) in next_completions() {
            record_completion(user_data, result);
        }
    }
}

/// Armed guard for a synchronous SQE that may reference caller-owned memory.
///
/// The guard is created immediately after publishing the SQE and is disarmed
/// only after its matching CQE is consumed. Its destructor preserves the same
/// invariant if stack unwinding crosses the post-submission wait loop.
struct SubmittedOperationGuard<'a> {
    file: &'a IoUringFile,
    ring: &'a mut IoUring,
    expected_user_data: u64,
    completed: bool,
}

impl<'a> SubmittedOperationGuard<'a> {
    fn new(file: &'a IoUringFile, ring: &'a mut IoUring, expected_user_data: u64) -> Self {
        Self {
            file,
            ring,
            expected_user_data,
            completed: false,
        }
    }

    fn drain_to_completion(&mut self) -> i32 {
        wait_until_submitted_completion(|| {
            if let Some(result) = self
                .file
                .drain_completions_locked(self.ring, Some(self.expected_user_data))
            {
                return (Ok(0), Some(result));
            }

            let wait_result = self.ring.submit_and_wait(1);
            let completion = self
                .file
                .drain_completions_locked(self.ring, Some(self.expected_user_data));
            (wait_result, completion)
        })
    }

    fn wait(mut self) -> i32 {
        let result = self.drain_to_completion();
        self.completed = true;
        result
    }
}

impl Drop for SubmittedOperationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _terminal_result = self.drain_to_completion();
            self.completed = true;
        }
    }
}

impl Drop for IoUringFileInner {
    fn drop(&mut self) {
        // Final teardown is a lifetime boundary for tracked test operations.
        // Cancellation is only a request; the matching CQE is the proof that
        // the kernel has released any referenced buffer.
        drain_tracked_until_quiescent(
            || any_ops_pending(self),
            || {
                let mut ring = self.ring.lock();

                for user_data in tracked_pending_user_data(self) {
                    let _ = ring
                        .submitter()
                        .register_sync_cancel(None, types::CancelBuilder::user_data(user_data));
                }

                wait_until_submitted_completion(|| {
                    let ready = ring
                        .completion()
                        .map(|cqe| (cqe.user_data(), cqe.result()))
                        .collect::<Vec<_>>();
                    if !ready.is_empty() {
                        return (Ok(0), Some(ready));
                    }

                    let wait_result = ring.submit_and_wait(1);
                    let ready = ring
                        .completion()
                        .map(|cqe| (cqe.user_data(), cqe.result()))
                        .collect::<Vec<_>>();
                    let completion = (!ready.is_empty()).then_some(ready);
                    (wait_result, completion)
                })
            },
            |user_data, result| {
                let _ = mark_tracked_op_complete(self, user_data, result);
            },
        );
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
    /// The constructor is synchronous, so those effects complete before return.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_flags(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644)
    }

    /// Opens a file with custom flags and mode.
    ///
    /// This constructor is synchronous. Mutating flags such as `O_CREAT` or
    /// `O_TRUNC` take effect before this function returns.
    pub fn open_with_flags(path: impl AsRef<Path>, flags: i32, mode: u32) -> io::Result<Self> {
        let path = path.as_ref();
        let c_path = path_to_cstring(path)?;
        crate::cx::io_gate::require_ambient_io("fs::IoUringFile::open")?;
        // Open the descriptor synchronously, then use the file-local io_uring
        // queue for data-path operations. This keeps ownership and cleanup
        // deterministic before any request can be submitted against the fd.
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
            trait_io: Mutex::new(TraitIoState::default()),
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
            trait_io: Mutex::new(TraitIoState::default()),
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
    /// Polling the returned future drives one `IORING_OP_WRITE` through its
    /// terminal completion and returns `Ready`. Dropping it before its first
    /// poll has no effect; cancellation cannot interleave inside the poll.
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
    /// This does not modify the file's current position. Its poll has the same
    /// synchronous-completion boundary as [`write`](Self::write).
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
    /// Polling drives `IORING_OP_FSYNC` with `IORING_FSYNC_DATASYNC` through
    /// terminal completion and returns `Ready`; dropping it unpolled has no
    /// effect.
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
    /// Polling drives `IORING_OP_FSYNC` through terminal completion and returns
    /// `Ready`; dropping it unpolled has no effect.
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
        let io = self.trait_io.lock();
        if let Some(TraitOperation::Read { start, .. }) = &io.pending {
            return *start;
        }
        self.inner
            .position
            .load(Ordering::Relaxed)
            .saturating_sub(io.unread_len() as u64)
    }

    fn checked_seek_target(base: u64, delta: i64) -> io::Result<u64> {
        base.checked_add_signed(delta)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek offset out of range"))
    }

    /// Sets the logical file position used by sequential read/write operations.
    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        self.prepare_synchronous_operation(true, true)?;
        // This synchronous call is a new seek, not a retry of a trait future
        // whose result another operation already collected.
        self.trait_io.lock().seek_credit = None;
        let _cursor_guard = self.inner.cursor_lock.lock();
        self.seek_locked(pos)
    }

    fn seek_locked(&self, pos: SeekFrom) -> io::Result<u64> {
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
    /// Uses a synchronous `ftruncate` syscall (no io_uring opcode for
    /// truncate), so the mutation completes before this function returns.
    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.prepare_synchronous_operation(true, true)?;
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
    pub fn metadata(&self) -> io::Result<Metadata> {
        let fd = self.inner.fd.as_raw_fd();
        // SAFETY: We borrow the fd temporarily; the OwnedFd still owns it.
        let std_file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        std_file.metadata().map(Metadata::from_std)
    }

    /// Changes the permissions on the underlying file synchronously.
    pub fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        let fd = self.inner.fd.as_raw_fd();
        let std_file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        std_file.set_permissions(perm.into_inner())
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

        let submitted = SubmittedOperationGuard::new(self, &mut ring, expected_user_data);
        Ok(submitted.wait())
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

/// Test-only owner for a deliberately pending operation.
///
/// Field order is safety-relevant: final file teardown drains the tracked SQE
/// before the owned buffer can be released. Forgetting this value leaks both
/// together, so it cannot expose freed memory to the kernel.
#[cfg(any(test, feature = "test-internals"))]
struct PendingTestOperation {
    file: Option<IoUringFile>,
    buffer: Vec<u8>,
}

#[cfg(any(test, feature = "test-internals"))]
impl PendingTestOperation {
    fn finish_buffer(mut self) -> Vec<u8> {
        drop(self.file.take());
        std::mem::take(&mut self.buffer)
    }

    fn drain(mut self) {
        drop(self.file.take());
    }
}

#[cfg(any(test, feature = "test-internals"))]
impl IoUringFile {
    fn submit_unknown_nop_for_test(&self, user_data: u64) -> io::Result<()> {
        let entry = opcode::Nop::new().build().user_data(user_data);
        let mut ring = self.inner.ring.lock();
        // SAFETY: NOP has no external buffer dependencies.
        unsafe {
            ring.submission()
                .push(&entry)
                .map_err(|_| io::Error::other("submission queue full for unknown CQE probe"))?;
        }
        ring.submit()?;
        Ok(())
    }

    fn require_unique_test_owner(&self) -> io::Result<()> {
        if Arc::strong_count(&self.inner) == 1 {
            Ok(())
        } else {
            Err(io::Error::other(
                "pending io_uring test operation requires a unique file owner",
            ))
        }
    }

    /// Submit a tracked test read without awaiting it.
    fn submit_pending_read_for_test(
        self,
        buffer_len: usize,
        offset: u64,
    ) -> io::Result<PendingTestOperation> {
        self.require_unique_test_owner()?;
        let mut buffer = vec![0; buffer_len];
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
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        )
        .offset(offset)
        .build()
        .user_data(user_data);

        let push_result = {
            let mut ring = self.inner.ring.lock();
            let push_result = self.push_entry_with_recovery(&mut ring, &entry);
            if push_result.is_ok() {
                // Once published, retain Pending even if submission reports an
                // error. Final inner teardown will submit/drain the request.
                let _ = ring.submit();
            }
            push_result
        };

        if let Err(err) = push_result {
            *self.inner.read_state.lock() = OpState::Idle;
            return Err(err);
        }

        Ok(PendingTestOperation {
            file: Some(self),
            buffer,
        })
    }

    /// Submit a tracked test write without awaiting it.
    fn submit_pending_write_for_test(
        self,
        buffer: Vec<u8>,
        offset: u64,
    ) -> io::Result<PendingTestOperation> {
        self.require_unique_test_owner()?;
        let user_data = self.allocate_user_data(OpKind::Write);
        {
            let mut state = self.inner.write_state.lock();
            if !matches!(*state, OpState::Idle) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "test pending write already registered",
                ));
            }
            *state = OpState::Pending {
                user_data,
                waker: None,
            };
        }

        let entry = opcode::Write::new(
            types::Fd(self.inner.fd.as_raw_fd()),
            buffer.as_ptr(),
            u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        )
        .offset(offset)
        .build()
        .user_data(user_data);

        let push_result = {
            let mut ring = self.inner.ring.lock();
            let push_result = self.push_entry_with_recovery(&mut ring, &entry);
            if push_result.is_ok() {
                let _ = ring.submit();
            }
            push_result
        };

        if let Err(err) = push_result {
            *self.inner.write_state.lock() = OpState::Idle;
            return Err(err);
        }

        Ok(PendingTestOperation {
            file: Some(self),
            buffer,
        })
    }

    fn submit_pending_sync_for_test(self, datasync: bool) -> io::Result<PendingTestOperation> {
        self.require_unique_test_owner()?;
        let kind = if datasync {
            OpKind::Fdatasync
        } else {
            OpKind::Fsync
        };
        let user_data = self.allocate_user_data(kind);
        {
            let mut state = self.inner.sync_state.lock();
            if !matches!(*state, OpState::Idle) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "test pending sync already registered",
                ));
            }
            *state = OpState::Pending {
                user_data,
                waker: None,
            };
        }

        let mut builder = opcode::Fsync::new(types::Fd(self.inner.fd.as_raw_fd()));
        if datasync {
            builder = builder.flags(types::FsyncFlags::DATASYNC);
        }
        let entry = builder.build().user_data(user_data);

        let push_result = {
            let mut ring = self.inner.ring.lock();
            let push_result = self.push_entry_with_recovery(&mut ring, &entry);
            if push_result.is_ok() {
                let _ = ring.submit();
            }
            push_result
        };

        if let Err(err) = push_result {
            *self.inner.sync_state.lock() = OpState::Idle;
            return Err(err);
        }

        Ok(PendingTestOperation {
            file: Some(self),
            buffer: Vec::new(),
        })
    }
}

// Reserve a high-bit namespace for synthetic completion-queue entries used by
// both the unit tests and the test-internals integration helpers.
#[cfg(any(test, feature = "test-internals"))]
const UNKNOWN_CQE_USER_DATA: u64 = 0xFF00_0000_DEAD_BEEF;

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub mod test_internals {
    use super::{IoUringFile, UNKNOWN_CQE_USER_DATA, any_ops_pending};
    use std::io;
    use std::path::Path;

    fn all_zero(bytes: &[u8]) -> bool {
        bytes.iter().all(|byte| *byte == 0)
    }

    fn payload_mismatch_error(operation: &str, expected: &[u8], actual: &[u8]) -> io::Error {
        io::Error::other(format!(
            "io_uring {operation} drop-drain mismatch: expected={:?} actual={:?}",
            String::from_utf8_lossy(expected),
            String::from_utf8_lossy(actual)
        ))
    }

    pub fn drop_drains_pending_read(path: &Path, payload: &[u8]) -> io::Result<&'static str> {
        std::fs::write(path, payload)?;
        let file = IoUringFile::open(path)?;
        let pending = file.submit_pending_read_for_test(payload.len(), 0)?;
        let buf = pending.finish_buffer();

        if buf != payload {
            if all_zero(&buf) {
                return Ok("cancelled");
            }
            return Err(payload_mismatch_error("read", payload, &buf));
        }
        Ok("completed")
    }

    pub fn drop_drains_pending_write(path: &Path, payload: &[u8]) -> io::Result<&'static str> {
        let file = IoUringFile::open_with_flags(
            path,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )?;

        let pending = file.submit_pending_write_for_test(payload.to_vec(), 0)?;
        pending.drain();

        let contents = std::fs::read(path)?;
        if contents.as_slice() != payload {
            if contents.is_empty() {
                return Ok("cancelled");
            }
            return Err(payload_mismatch_error("write", payload, &contents));
        }
        Ok("completed")
    }

    pub fn drop_drains_pending_sync(path: &Path, payload: &[u8]) -> io::Result<&'static str> {
        std::fs::write(path, payload)?;
        let file = IoUringFile::open_with_flags(path, libc::O_RDWR, 0)?;

        let pending = file.submit_pending_sync_for_test(false)?;
        pending.drain();

        let contents = std::fs::read(path)?;
        if contents.as_slice() != payload {
            return Err(payload_mismatch_error("sync", payload, &contents));
        }
        Ok("drained")
    }

    pub async fn ignores_unknown_completion_before_read(
        path: &Path,
        payload: &[u8],
    ) -> io::Result<()> {
        std::fs::write(path, payload)?;
        let file = IoUringFile::open(path)?;

        file.submit_unknown_nop_for_test(UNKNOWN_CQE_USER_DATA)?;

        let mut buf = vec![0_u8; payload.len()];
        let n = file.read(&mut buf).await?;
        if n != payload.len() || buf.as_slice() != payload {
            return Err(payload_mismatch_error(
                "unknown-cqe-read",
                payload,
                &buf[..n],
            ));
        }

        Ok(())
    }

    pub async fn ignores_unknown_completion_before_write(
        path: &Path,
        payload: &[u8],
    ) -> io::Result<()> {
        let file = IoUringFile::open_with_flags(
            path,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )?;

        file.submit_unknown_nop_for_test(UNKNOWN_CQE_USER_DATA)?;

        let n = file.write(payload).await?;
        if n != payload.len() {
            return Err(payload_mismatch_error(
                "unknown-cqe-write-len",
                payload,
                &payload[..n.min(payload.len())],
            ));
        }
        file.sync_all().await?;
        drop(file);

        let contents = std::fs::read(path)?;
        if contents.as_slice() != payload {
            return Err(payload_mismatch_error(
                "unknown-cqe-write",
                payload,
                &contents,
            ));
        }

        Ok(())
    }

    pub async fn ignores_unknown_completion_before_sync(
        path: &Path,
        payload: &[u8],
    ) -> io::Result<()> {
        std::fs::write(path, payload)?;
        let file = IoUringFile::open_with_flags(path, libc::O_RDWR, 0)?;

        file.submit_unknown_nop_for_test(UNKNOWN_CQE_USER_DATA)?;

        file.sync_all().await?;
        drop(file);

        let contents = std::fs::read(path)?;
        if contents.as_slice() != payload {
            return Err(payload_mismatch_error(
                "unknown-cqe-sync",
                payload,
                &contents,
            ));
        }

        Ok(())
    }

    pub fn truncate_is_sync_boundary(path: &Path, payload: &[u8], len: u64) -> io::Result<u64> {
        std::fs::write(path, payload)?;
        let file = IoUringFile::open_with_flags(path, libc::O_RDWR, 0)?;

        file.set_len(len)?;
        if any_ops_pending(&file.inner) {
            return Err(io::Error::other(
                "io_uring set_len boundary left pending operation state",
            ));
        }

        let actual_len = file.metadata()?.len();
        drop(file);
        Ok(actual_len)
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
        // Drive the file-local ring to the matching completion for this
        // future. Completion records for other operations are retained in the
        // per-operation state and woken via mark_tracked_op_complete.
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(polled_after_completion_error("read")));
        }
        let result = if this.update_position {
            if let Err(error) = this.file.prepare_synchronous_operation(true, false) {
                this.done = true;
                return Poll::Ready(Err(error));
            }
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
            if let Err(error) = this.file.prepare_synchronous_operation(false, false) {
                this.done = true;
                return Poll::Ready(Err(error));
            }
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
            if let Err(error) = this.file.prepare_synchronous_operation(true, true) {
                this.done = true;
                return Poll::Ready(Err(error));
            }
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
            // A positioned mutation must invalidate unread trait data too,
            // without changing the caller's logical sequential position.
            if let Err(error) = this.file.prepare_synchronous_operation(true, true) {
                this.done = true;
                return Poll::Ready(Err(error));
            }
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

        let result = this
            .file
            .prepare_synchronous_operation(false, false)
            .and_then(|()| this.file.blocking_sync(this.datasync));
        this.done = true;
        Poll::Ready(result)
    }
}

// Trait operations own their memory until the matching CQE is observed on the
// worker. Only their terminal result crosses back to the executor.
const TRAIT_IO_CHUNK_BYTES: usize = 128 * 1024;
type TraitIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

enum TraitOperation {
    Read {
        future: TraitIoFuture<Vec<u8>>,
        // Report the logical cursor until the caller consumes the result.
        // The worker still selects its actual offset under cursor_lock.
        start: u64,
    },
    Write {
        future: TraitIoFuture<usize>,
        chunk: Arc<Vec<u8>>,
    },
    Sync(TraitIoFuture<()>),
    Seek {
        future: TraitIoFuture<u64>,
        position: SeekFrom,
    },
}

struct TraitReadAhead {
    bytes: Vec<u8>,
    consumed: usize,
}

struct TraitWriteCredit {
    chunk: Arc<Vec<u8>>,
    result: io::Result<usize>,
}

struct TraitSeekCredit {
    position: SeekFrom,
    result: io::Result<u64>,
}

fn copy_io_error(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()),
        io::Error::from_raw_os_error,
    )
}

/// A split reader/writer may both wait for the same serialized operation.
/// Forward its wake to each role instead of replacing the writer's wake when
/// a reader or flush starts waiting. User callbacks run outside this mutex.
#[derive(Default)]
struct TraitWaiters {
    slots: Mutex<[Option<Waker>; 4]>,
}

impl TraitWaiters {
    fn register(&self, role: usize, waker: &Waker) {
        let incoming = waker.clone();
        let old = self.slots.lock()[role].replace(incoming);
        drop(old);
    }

    fn clear(&self, role: usize) {
        let old = self.slots.lock()[role].take();
        drop(old);
    }
}

impl Wake for TraitWaiters {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.slots.lock());
        let mut first_panic = None;
        for waker in waiters.into_iter().flatten() {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()))
            {
                if first_panic.is_none() {
                    first_panic = Some(payload);
                } else {
                    std::mem::forget(payload);
                }
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }
}

#[derive(Default)]
struct TraitIoState {
    pending: Option<TraitOperation>,
    read_ahead: Option<TraitReadAhead>,
    write_credit: Option<TraitWriteCredit>,
    seek_credit: Option<TraitSeekCredit>,
    waiters: Arc<TraitWaiters>,
}

impl std::fmt::Debug for TraitIoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraitIoState")
            .field("pending", &self.pending.is_some())
            .field("unread_bytes", &self.unread_len())
            .field("retained_write_credit", &self.write_credit.is_some())
            .field("retained_seek_credit", &self.seek_credit.is_some())
            .finish()
    }
}

impl TraitIoState {
    fn unread_len(&self) -> usize {
        self.read_ahead
            .as_ref()
            .map_or(0, |read| read.bytes.len() - read.consumed)
    }

    /// Called only after the outstanding worker has returned. Exclusive trait
    /// access excludes concurrent synchronous cursor operations; synchronous
    /// callers take the cursor lock before invoking it.
    fn rewind_read_ahead(&mut self, inner: &IoUringFileInner) -> io::Result<()> {
        let unread = self.unread_len() as u64;
        if unread != 0 {
            let position = inner
                .position
                .load(Ordering::Relaxed)
                .checked_sub(unread)
                .ok_or_else(|| io::Error::other("io_uring read-ahead exceeds cursor position"))?;
            inner.position.store(position, Ordering::Relaxed);
        }
        self.read_ahead = None;
        Ok(())
    }

    fn settle(
        &mut self,
        cx: &mut Context<'_>,
        retain_write: bool,
        retain_seek: bool,
    ) -> Poll<io::Result<()>> {
        let Some(operation) = self.pending.take() else {
            return Poll::Ready(Ok(()));
        };
        match operation {
            TraitOperation::Read { mut future, start } => match future.as_mut().poll(cx) {
                Poll::Pending => {
                    self.pending = Some(TraitOperation::Read { future, start });
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    let bytes = result?;
                    if !bytes.is_empty() {
                        self.read_ahead = Some(TraitReadAhead { bytes, consumed: 0 });
                    }
                    Poll::Ready(Ok(()))
                }
            },
            TraitOperation::Write { mut future, chunk } => match future.as_mut().poll(cx) {
                Poll::Pending => {
                    self.pending = Some(TraitOperation::Write { future, chunk });
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    if !retain_write {
                        return Poll::Ready(result.map(|_| ()));
                    }
                    // The observer sees the failure too, but the writer keeps
                    // its original error and must not silently resubmit on its
                    // next poll. Preserve errno for errors produced by the OS.
                    let observed = result.as_ref().map(|_| ()).map_err(copy_io_error);
                    self.write_credit = Some(TraitWriteCredit { chunk, result });
                    Poll::Ready(observed)
                }
            },
            TraitOperation::Sync(mut future) => match future.as_mut().poll(cx) {
                Poll::Pending => {
                    self.pending = Some(TraitOperation::Sync(future));
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result),
            },
            TraitOperation::Seek {
                mut future,
                position,
            } => match future.as_mut().poll(cx) {
                Poll::Pending => {
                    self.pending = Some(TraitOperation::Seek { future, position });
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    if !retain_seek {
                        return Poll::Ready(result.map(|_| ()));
                    }
                    let observed = result.as_ref().map(|_| ()).map_err(copy_io_error);
                    self.seek_credit = Some(TraitSeekCredit { position, result });
                    Poll::Ready(observed)
                }
            },
        }
    }
}

fn poll_trait_operation<T>(
    state: &mut TraitIoState,
    role: usize,
    cx: &Context<'_>,
    poll: impl FnOnce(&mut TraitIoState, &mut Context<'_>) -> Poll<T>,
) -> Poll<T> {
    let waiters = Arc::clone(&state.waiters);
    waiters.register(role, cx.waker());
    let waker = Waker::from(Arc::clone(&waiters));
    let result = poll(state, &mut Context::from_waker(&waker));
    if result.is_ready() {
        waiters.clear(role);
    }
    result
}

impl IoUringFile {
    fn prepare_synchronous_operation(&self, rewind: bool, new_write: bool) -> io::Result<()> {
        let mut state = self.trait_io.lock();
        if state.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "collect the pending io_uring trait operation before a synchronous operation",
            ));
        }
        if rewind {
            let _cursor_guard = self.inner.cursor_lock.lock();
            state.rewind_read_ahead(&self.inner)?;
        }
        if new_write {
            state.write_credit = None;
        }
        Ok(())
    }

    fn submit_trait_io<T: Send + 'static>(
        inner: &Arc<IoUringFileInner>,
        operation: impl FnOnce(&Self) -> io::Result<T> + Send + 'static,
    ) -> TraitIoFuture<T> {
        let file = Self {
            inner: Arc::clone(inner),
            trait_io: Mutex::new(TraitIoState::default()),
        };
        let run = move || {
            let _cursor_guard = file.inner.cursor_lock.lock();
            operation(&file)
        };
        // Match File's placement policy without restoring restricted SPAWN
        // authority. A rejected pool or absent pool retains the inline fallback.
        match crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance()) {
            Some(pool) => Box::pin(crate::runtime::spawn_blocking::spawn_blocking_on_pool(
                pool, run,
            )),
            None => Box::pin(std::future::ready(run())),
        }
    }
}

impl AsyncRead for IoUringFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let inner = &this.inner;
        poll_trait_operation(this.trait_io.get_mut(), 0, cx, |state, task| loop {
            if let Some(read) = state.read_ahead.as_mut() {
                let count = (read.bytes.len() - read.consumed).min(buf.remaining());
                buf.unfilled()[..count]
                    .copy_from_slice(&read.bytes[read.consumed..read.consumed + count]);
                buf.advance(count);
                read.consumed += count;
                if read.consumed == read.bytes.len() {
                    state.read_ahead = None;
                }
                return Poll::Ready(Ok(()));
            }
            match state.pending.take() {
                Some(TraitOperation::Read { mut future, start }) => {
                    match future.as_mut().poll(task) {
                        Poll::Pending => {
                            state.pending = Some(TraitOperation::Read { future, start });
                            return Poll::Pending;
                        }
                        Poll::Ready(result) => {
                            let bytes = result?;
                            if bytes.is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            state.read_ahead = Some(TraitReadAhead { bytes, consumed: 0 });
                        }
                    }
                }
                None => {
                    let length = buf.remaining().min(TRAIT_IO_CHUNK_BYTES);
                    let start = inner.position.load(Ordering::Relaxed);
                    let future = Self::submit_trait_io(inner, move |file| {
                        let mut bytes = vec![0; length];
                        let offset = file.inner.position.load(Ordering::Relaxed);
                        let count = file.blocking_read_at(&mut bytes, offset)?;
                        file.inner
                            .position
                            .store(offset.saturating_add(count as u64), Ordering::Relaxed);
                        bytes.truncate(count);
                        Ok(bytes)
                    });
                    state.pending = Some(TraitOperation::Read { future, start });
                }
                other => {
                    state.pending = other;
                    match state.settle(task, true, true) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    }
                }
            }
        })
    }
}

impl AsyncWrite for IoUringFile {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let inner = &this.inner;
        poll_trait_operation(this.trait_io.get_mut(), 1, cx, |state, task| {
            if let Some(credit) = state.write_credit.take()
                && buf.starts_with(&credit.chunk)
            {
                return Poll::Ready(credit.result);
            }
            loop {
                match state.pending.take() {
                    Some(TraitOperation::Write { mut future, chunk })
                        if buf.starts_with(&chunk) =>
                    {
                        return match future.as_mut().poll(task) {
                            Poll::Pending => {
                                state.pending = Some(TraitOperation::Write { future, chunk });
                                Poll::Pending
                            }
                            Poll::Ready(result) => Poll::Ready(result),
                        };
                    }
                    None => {
                        state.rewind_read_ahead(inner)?;
                        let chunk = Arc::new(buf[..buf.len().min(TRAIT_IO_CHUNK_BYTES)].to_vec());
                        let submitted = Arc::clone(&chunk);
                        let future = Self::submit_trait_io(inner, move |file| {
                            let offset = file.inner.position.load(Ordering::Relaxed);
                            let written = file.blocking_write_at(&submitted, offset)?;
                            file.inner
                                .position
                                .store(offset.saturating_add(written as u64), Ordering::Relaxed);
                            Ok(written)
                        });
                        state.pending = Some(TraitOperation::Write { future, chunk });
                    }
                    other => {
                        state.pending = other;
                        match state.settle(task, false, true) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(result) => result?,
                        }
                    }
                }
            }
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &this.inner;
        poll_trait_operation(this.trait_io.get_mut(), 2, cx, |state, task| loop {
            match state.pending.take() {
                Some(TraitOperation::Sync(mut future)) => {
                    return match future.as_mut().poll(task) {
                        Poll::Pending => {
                            state.pending = Some(TraitOperation::Sync(future));
                            Poll::Pending
                        }
                        Poll::Ready(result) => Poll::Ready(result),
                    };
                }
                None => {
                    state.pending = Some(TraitOperation::Sync(Self::submit_trait_io(
                        inner,
                        |file| file.blocking_sync(true),
                    )));
                }
                other => {
                    state.pending = other;
                    match state.settle(task, true, true) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    }
                }
            }
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncSeek for IoUringFile {
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        let inner = &this.inner;
        poll_trait_operation(this.trait_io.get_mut(), 3, cx, |state, task| {
            // A foreign operation may have collected this seek and then moved
            // the cursor itself. Report the original result without applying a
            // relative offset again or discarding a later write's completion.
            if let Some(credit) = state.seek_credit.take()
                && credit.position == pos
            {
                return Poll::Ready(credit.result);
            }
            // A deliberate cursor operation starts a new write sequence,
            // matching File: identical bytes after seeking are a new write.
            state.write_credit = None;
            loop {
                match state.pending.take() {
                    Some(TraitOperation::Seek {
                        mut future,
                        position,
                    }) if position == pos => {
                        return match future.as_mut().poll(task) {
                            Poll::Pending => {
                                state.pending = Some(TraitOperation::Seek { future, position });
                                Poll::Pending
                            }
                            Poll::Ready(result) => Poll::Ready(result),
                        };
                    }
                    None => {
                        state.rewind_read_ahead(inner)?;
                        state.pending = Some(TraitOperation::Seek {
                            future: Self::submit_trait_io(inner, move |file| file.seek_locked(pos)),
                            position: pos,
                        });
                    }
                    other => {
                        state.pending = other;
                        match state.settle(task, false, false) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(result) => result?,
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "uring_inline_tests.rs"]
mod tests;
